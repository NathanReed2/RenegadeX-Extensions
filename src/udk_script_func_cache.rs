//! Memoises `UObject::FindFunction`, the name-to-`UFunction` resolver every
//! script entry path funnels through.
//!
//! # What the stock engine does
//!
//! `UObject::FindFunction( FName, UBOOL Global )` resolves a function by name
//! with two chain walks - the object's state chain, then its class chain:
//!
//! ```text
//! for( SearchState = StateFrame->StateNode; SearchState; SearchState = SearchState->GetSuperState() )
//!     Function = SearchState->FuncMap.FindRef(InName);
//! for( SearchClass = GetClass(); SearchClass; SearchClass = SearchClass->GetSuperClass() )
//!     Function = SearchClass->FuncMap.FindRef(InName);
//! ```
//!
//! Each level costs three dependent loads - hash bucket index, pair-chain walk,
//! then `SuperStruct` - and `UClass` objects are scattered across the heap, so
//! most of them miss cache. There is no memoisation anywhere: the same question
//! is asked again from scratch on every call.
//!
//! It is asked constantly. Every generated `eventXxx()` wrapper calls
//! `FindFunctionChecked` (99 call sites in the binary; `EngineClasses.h` alone
//! declares 201 of them), as do `execVirtualFunction`, `execGlobalFunction`,
//! `execDelegateFunction` and `ProcessDelegate`. `AActor::UpdateTimers`
//! re-resolves every timer's function by name on each fire.
//!
//! The worst of it is `AActor::Tick`, which calls `eventTick(DeltaSeconds)`
//! unconditionally - there is no `bScriptTick` gate, though `TickSpecial` right
//! below it does have `bScriptTickSpecial`. `ProcessEvent` only rejects on
//! `FUNC_Defined` *after* the lookup completes, so every ticking actor pays a
//! full chain walk every frame to discover that its class does not override
//! `Tick`. Measured over the Firestorm script tree, the median class is 5 deep
//! and `Rx_Vehicle_Humvee` and `Rx_Defence` are 9, with 1,293 of 6,836 classes
//! at 8 or deeper - roughly 27 mostly-missing dependent loads per actor per
//! frame, to accomplish nothing.
//!
//! # What this module changes
//!
//! It detours `FindFunction` and puts a direct-mapped cache in front of it,
//! keyed on the three things the answer actually depends on: the effective
//! state node, the class, and the name. A hit replaces the whole walk with one
//! hash and one comparison.
//!
//! `Global` is deliberately *not* part of the key. The engine consults the
//! state chain only when `Global` is FALSE, so a global lookup and a lookup on
//! an object with no state frame ask the identical question and the engine
//! returns the identical `UFunction`. Collapsing the state node to zero for
//! both captures that exactly and lets the two share cache entries.
//!
//! A NULL result is cached like any other. That is not an edge case, it is the
//! case that matters most - "this class has no script `Tick`" is precisely the
//! answer being recomputed thousands of times a second.
//!
//! # Invalidation
//!
//! Cached `UFunction` pointers only go stale when script objects are destroyed,
//! which happens when a package is unloaded and the garbage collector reaps it.
//! During a level, script classes stay reachable through their `UPackage`, so
//! the mid-level incremental purges never touch them; the exposure is level
//! transitions, which always run a full `CollectGarbage`.
//!
//! So `CollectGarbage` is detoured to bump a global generation counter, once on
//! the way in and once on the way out - the second bump discards anything
//! filled while the collector was running and objects were still being
//! destroyed. A cache whose generation no longer matches is cleared wholesale
//! before its next use, which also lets one counter invalidate every thread's
//! cache without touching another thread's memory.
//!
//! The cache is thread-local and holds no locks, so the lookup path has no
//! atomic read-modify-write on it; script runs on the game thread, and any
//! other thread that calls `FindFunction` simply gets its own table.
//!
//! # Disabling
//!
//! `-NOSCRIPTFUNCCACHE` on the command line skips both detours entirely, which
//! restores stock behaviour for isolating a regression.
//!
//! RVAs were mapped in Ghidra from the symbol-bearing 2013
//! `UDK Source Build with symbols/UDK.exe` to `RenXSDK/UDK.exe`. `FindFunction`
//! matched by a unique 17-byte prologue search, and `CollectGarbage` diffs
//! 488 of 489 instructions equal against its symbol-bearing twin. The struct
//! offsets below were read back out of the RenXSDK decompilation rather than
//! assumed from the 2013 headers.

#![cfg(target_arch = "x86_64")]

use anyhow::{bail, Context};
use retour::static_detour;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;

/// `UObject::StateFrame`, confirmed against `ProcessInternal`'s probe-mask read
/// in both builds.
const UOBJECT_STATE_FRAME: usize = 0x20;
/// `FStateFrame::StateNode`. UE3 packs its structs to 4 bytes, which is why
/// this and the `FFrame` members are not 8-aligned.
const STATE_FRAME_STATE_NODE: usize = 0x44;
/// `UObject::Class`.
const UOBJECT_CLASS: usize = 0x50;

/// Command line switch that stands this module down.
const DISABLE_SWITCH: &str = "NOSCRIPTFUNCCACHE";

/// A function whose prologue is verified before a detour is written over it.
struct HookTarget {
    name: &'static str,
    rva: usize,
    prologue: &'static [u8],
}

const FIND_FUNCTION: HookTarget = HookTarget {
    name: "UObject::FindFunction",
    rva: 0x0026_CC70,
    prologue: &[
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x4C, 0x8B, 0x51, 0x20, 0x33, 0xC0, 0x48, 0x8B, 0xD9, 0x4D,
        0x85, 0xD2,
    ],
};

const COLLECT_GARBAGE: HookTarget = HookTarget {
    name: "UObject::CollectGarbage",
    rva: 0x0029_9E10,
    prologue: &[
        0x48, 0x8B, 0xC4, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8,
        0xF8, 0xFE, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xE0, 0x01, 0x00, 0x00,
    ],
};

/// `UFunction* UObject::FindFunction( FName InName, UBOOL Global ) const`.
/// `FName` is two packed `INT`s and passes by value in a single register.
type FindFunction = extern "C" fn(*mut c_void, u64, u32) -> *mut c_void;
/// `void UObject::CollectGarbage( EObjectFlags KeepFlags, UBOOL bPerformFullPurge )`.
type CollectGarbage = extern "C" fn(u64, u32);

static_detour! {
    static FindFunctionHook: extern "C" fn(*mut c_void, u64, u32) -> *mut c_void;
}

static_detour! {
    static CollectGarbageHook: extern "C" fn(u64, u32);
}

/// Bumped either side of a garbage collection. A thread-local cache carrying
/// any other value is stale in its entirety.
static GENERATION: AtomicU64 = AtomicU64::new(1);

/// Direct mapped, so a collision is a miss rather than a probe - a miss just
/// calls the engine and is always correct.
const CACHE_SLOTS: usize = 4096;

#[derive(Clone, Copy)]
struct Slot {
    state_node: usize,
    class: usize,
    name: u64,
    function: usize,
}

/// `class` is never zero in a live entry, so it doubles as the empty sentinel
/// and a cached NULL `function` stays distinguishable from an unused slot.
const EMPTY: Slot = Slot {
    state_node: 0,
    class: 0,
    name: 0,
    function: 0,
};

struct Cache {
    generation: u64,
    hits: u64,
    misses: u64,
    slots: Box<[Slot]>,
}

thread_local! {
    static CACHE: UnsafeCell<Cache> = UnsafeCell::new(Cache {
        // Never equal to the initial GENERATION, so the first lookup on a
        // thread takes the reset path and adopts the current generation.
        generation: 0,
        hits: 0,
        misses: 0,
        slots: vec![EMPTY; CACHE_SLOTS].into_boxed_slice(),
    });
}

impl HookTarget {
    /// Validates the prologue and returns the address to detour.
    fn resolve(&self) -> anyhow::Result<*const ()> {
        let range = UDK_RANGE.get().context("UDK_RANGE not set")?;
        let address = range
            .start
            .checked_add(self.rva)
            .with_context(|| format!("{} address overflow", self.name))?;
        let end = address
            .checked_add(self.prologue.len())
            .with_context(|| format!("{} end overflow", self.name))?;
        if end > range.end {
            bail!("{} lies outside UDK.exe", self.name);
        }

        let actual =
            unsafe { std::slice::from_raw_parts(address as *const u8, self.prologue.len()) };
        if actual != self.prologue {
            bail!(
                "{} validation failed at RVA 0x{:X}: expected {:02X?}, found {:02X?}",
                self.name,
                self.rva,
                self.prologue,
                actual
            );
        }
        Ok(address as *const ())
    }
}

/// Mixes the three key fields down to a slot. Class and state node are heap
/// pointers whose low bits are alignment padding, so each is multiplied by an
/// odd constant to carry entropy upward before the fold.
fn slot_index(state_node: usize, class: usize, name: u64) -> usize {
    let mut hash = name.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    hash ^= (class as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    hash ^= (state_node as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93);
    ((hash >> 29) ^ hash) as usize & (CACHE_SLOTS - 1)
}

/// Reads the two fields the answer depends on. Returns `None` when the object
/// cannot be keyed, in which case the caller must not consult the cache.
unsafe fn key_of(object: *mut c_void, global: u32) -> Option<(usize, usize)> {
    let base = object as *const u8;
    let class = base.add(UOBJECT_CLASS).cast::<usize>().read();
    if class == 0 {
        return None;
    }

    // The engine walks the state chain only for a non-global lookup, so a
    // global one keys the same as a stateless object and shares its entries.
    let state_frame = base.add(UOBJECT_STATE_FRAME).cast::<usize>().read();
    let state_node = if global == 0 && state_frame != 0 {
        (state_frame as *const u8)
            .add(STATE_FRAME_STATE_NODE)
            .cast::<usize>()
            .read()
    } else {
        0
    };

    Some((state_node, class))
}

extern "C" fn find_function_hook(object: *mut c_void, name: u64, global: u32) -> *mut c_void {
    if object.is_null() {
        return FindFunctionHook.call(object, name, global);
    }

    let Some((state_node, class)) = (unsafe { key_of(object, global) }) else {
        return FindFunctionHook.call(object, name, global);
    };

    let generation = GENERATION.load(Ordering::Relaxed);
    let index = slot_index(state_node, class, name);

    let cached = CACHE.with(|cache| {
        // Sound because the cache is thread-local and nothing it calls
        // re-enters this function.
        let cache = unsafe { &mut *cache.get() };
        if cache.generation != generation {
            cache.slots.fill(EMPTY);
            cache.generation = generation;
            return None;
        }

        let slot = cache.slots[index];
        if slot.class == class && slot.state_node == state_node && slot.name == name {
            cache.hits += 1;
            Some(slot.function)
        } else {
            None
        }
    });

    if let Some(function) = cached {
        return function as *mut c_void;
    }

    let function = FindFunctionHook.call(object, name, global);

    CACHE.with(|cache| {
        let cache = unsafe { &mut *cache.get() };
        cache.misses += 1;
        // A collection that landed during the call above moved the generation
        // on; that answer is not safe to keep.
        if cache.generation == GENERATION.load(Ordering::Relaxed) {
            cache.slots[index] = Slot {
                state_node,
                class,
                name,
                function: function as usize,
            };
        }
    });

    function
}

extern "C" fn collect_garbage_hook(keep_flags: u64, full_purge: u32) {
    // Before, so nothing the collector itself asks for is answered from
    // entries that describe objects it is about to reap.
    GENERATION.fetch_add(1, Ordering::Relaxed);
    CollectGarbageHook.call(keep_flags, full_purge);
    // After, to discard anything filled while objects were being destroyed.
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

/// Lifetime hit and miss counts for the calling thread. Script runs on the
/// game thread, so reading this from a game-thread hook reports the numbers
/// that matter.
pub fn stats() -> (u64, u64) {
    CACHE.with(|cache| {
        let cache = unsafe { &*cache.get() };
        (cache.hits, cache.misses)
    })
}

fn disabled() -> bool {
    std::env::args_os().any(|argument| {
        argument
            .to_string_lossy()
            .to_ascii_uppercase()
            .trim_start_matches(['-', '/'])
            == DISABLE_SWITCH
    })
}

pub fn init() -> anyhow::Result<()> {
    if disabled() {
        debug_log!("udk_script_func_cache disabled by -{}", DISABLE_SWITCH);
        return Ok(());
    }

    let find_function_address = FIND_FUNCTION.resolve()?;
    let collect_garbage_address = COLLECT_GARBAGE.resolve()?;

    unsafe {
        let find_function: FindFunction = std::mem::transmute(find_function_address);
        FindFunctionHook
            .initialize(find_function, |object, name, global| {
                find_function_hook(object, name, global)
            })
            .context("failed to set up UObject::FindFunction hook")?;

        let collect_garbage: CollectGarbage = std::mem::transmute(collect_garbage_address);
        CollectGarbageHook
            .initialize(collect_garbage, |keep_flags, full_purge| {
                collect_garbage_hook(keep_flags, full_purge)
            })
            .context("failed to set up UObject::CollectGarbage hook")?;

        FindFunctionHook
            .enable()
            .context("failed to enable UObject::FindFunction hook")?;
        CollectGarbageHook
            .enable()
            .context("failed to enable UObject::CollectGarbage hook")?;
    }

    debug_log!("udk_script_func_cache::init done");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{slot_index, CACHE_SLOTS};

    #[test]
    fn slot_index_stays_in_range() {
        for name in 0..64u64 {
            for step in 0..64usize {
                let index = slot_index(0x1000 + step * 8, 0x2000 + step * 16, name);
                assert!(index < CACHE_SLOTS);
            }
        }
    }

    #[test]
    fn distinct_keys_mostly_land_in_distinct_slots() {
        // A direct mapped cache only pays off if realistic keys spread out.
        // Class and state pointers are 16-byte aligned heap addresses and names
        // are small dense integers, which is the shape modelled here.
        let mut seen = std::collections::HashSet::new();
        for class in 0..64usize {
            for name in 0..16u64 {
                seen.insert(slot_index(0, 0x1400_0000 + class * 48, name));
            }
        }
        assert!(
            seen.len() * 10 >= 64 * 16 * 8,
            "hash collapsed: {} distinct slots for 1024 keys",
            seen.len()
        );
    }

    #[test]
    fn state_node_participates_in_the_key() {
        // Two objects of the same class in different states must not share an
        // entry; the state chain is searched first and can shadow the class.
        assert_ne!(
            slot_index(0x3000, 0x2000, 7),
            slot_index(0x4000, 0x2000, 7),
            "state node did not affect the slot"
        );
    }
}
