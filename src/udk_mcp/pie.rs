//! Play In Editor: what it is doing, and starting and stopping it.
//!
//! # Why reading is separate from controlling
//!
//! "Is the map running?" is a question a model needs to answer before almost
//! anything else - a property read during PIE is reading the play world's copy,
//! not the map on disk, and an actor edit made while PIE is up is discarded when
//! it ends. So the status half is a plain read and lives under its own
//! capability, and it keeps working when the control half is denied. A model
//! that can see PIE is running but cannot stop it is in a *better* position than
//! one that cannot see it at all.
//!
//! # How the lifecycle is reached
//!
//! `UEditorEngine::PlayMap` does not start anything. It records where to play,
//! sets `bIsPlayWorldQueued`, and returns; the editor's own `Tick` notices the
//! flag on a later frame and calls `StartQueuedPlayMapRequest`. That is exactly
//! the shape this bridge wants - the request is cheap and non-blocking, the
//! engine does the work on its own schedule, and there is no way for us to hold
//! the editor thread inside a map load. It is also why starting PIE reports
//! "queued" rather than "started": at the moment the call returns, it is.
//!
//! Stopping is the opposite. `UEditorEngine::EndPlayMap` tears the play world
//! down synchronously, and its first statement is `check(PlayWorld)` - a UE3
//! `check` in a release build is a fatal error, not a silent no-op. So the
//! null test here is not defensive tidiness; calling it with no play world would
//! take the editor down with it.
//!
//! # Where the numbers came from
//!
//! `PlayMap`'s RVA was confirmed by its own fingerprint rather than by trusting
//! a symbol: it is the only function in this area that loads `VK_CONTROL` into
//! `GetAsyncKeyState` and tests the result against `0x8000`, which is the
//! "hold Ctrl to start in spectator mode" branch. Reading its stores then gave
//! every member offset below for free, which is why the byte guard covers the
//! first store: if `PlayWorldLocation` ever moves, the guard fails rather than
//! the write landing somewhere else in the engine.
//!
//! `EndPlayMap` was not taken from a symbol at all. The name lookup pointed at
//! `USpeedTreeComponent::GetPrivateStaticClass`, which is `/OPT:ICF` folding
//! doing what it does to identical template bodies. It was recovered instead
//! from the virtual table: in the symbolized 2013 build, `EndPlayMap` sits
//! `0x3D8` past `UUnrealEdEngine::Tick` in two independent engine vtables, and
//! applying that same delta to both of the 2015 build's `Tick` slots yields one
//! address, twice.

use std::ffi::c_void;

use super::{image_address, read_pointer};

/// `UEditorEngine::PlayMap`. Queues a play request; does not start one.
const PLAY_MAP_RVA: usize = 0x0102_6BB0;
/// `UEditorEngine::EndPlayMap`. Synchronous teardown, and fatal without a world.
const END_PLAY_MAP_RVA: usize = 0x0103_9100;

/// All relative to the `UEditorEngine` subobject, which for `UUnrealEdEngine` is
/// the object pointer itself - it is the primary base, unlike the secondary
/// `FExec` base that `renx_exec` has to adjust for.
const PLAY_WORLD_OFFSET: usize = 0xAD0;
const PLAY_WORLD_LOCATION_OFFSET: usize = 0xAD8;
const PLAY_WORLD_ROTATION_OFFSET: usize = 0xAE4;
/// UE3 packs consecutive `BITFIELD x:1` members into one dword.
const PLAY_FLAGS_OFFSET: usize = 0xAF0;
const PLAY_WORLD_DESTINATION_OFFSET: usize = 0xAF4;
const PLAY_IN_EDITOR_VIEWPORT_INDEX_OFFSET: usize = 0xB1C;

const FLAG_QUEUED: u32 = 1 << 0;
const FLAG_SPECTATOR: u32 = 1 << 1;
const FLAG_HAS_PLACEMENT: u32 = 1 << 2;
const FLAG_MOBILE_PREVIEW: u32 = 1 << 3;
const FLAG_MOVIE_CAPTURE: u32 = 1 << 4;

/// `PUSH RBX; SUB RSP,0x30; MOV RBX,RCX; TEST RDX,RDX; JZ; MOV EAX,[RDX];
/// MOV [RCX+0xAD8],EAX` - the prologue through the first `PlayWorldLocation`
/// store, so the guard covers the member offset this module writes through and
/// not merely the entry point.
const PLAY_MAP_GUARD: &[u8] = &[
    0x40, 0x53, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0xD9, 0x48, 0x85, 0xD2, 0x74, 0x55, 0x8B, 0x02,
    0x89, 0x81, 0xD8, 0x0A, 0x00, 0x00,
];

/// The large-frame prologue of `EndPlayMap`: every non-volatile register and two
/// XMM saves before a 0x1C8 frame, then `MOV R14,RCX`. Recovered from a vtable
/// rather than a symbol, so this guard is the only thing standing between a
/// wrong slot and a call into arbitrary engine code.
const END_PLAY_MAP_GUARD: &[u8] = &[
    0x48, 0x8B, 0xC4, 0x48, 0x89, 0x48, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41,
    0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0xF8, 0xFE, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xC8, 0x01, 0x00,
    0x00, 0x4C, 0x8B, 0xF1,
];

type PlayMapFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, i32, i32, u32, u32);
type EndPlayMapFn = unsafe extern "C" fn(*mut c_void);

/// `-1` means "in this editor" rather than an index into the console container.
const DESTINATION_IN_EDITOR: i32 = -1;
/// `-1` means a standalone PIE window rather than a specific level viewport.
const VIEWPORT_STANDALONE: i32 = -1;

fn guarded(rva: usize, guard: &[u8], name: &str) -> Result<usize, String> {
    let address = image_address(rva, guard.len(), name).map_err(|error| error.to_string())?;
    let actual = unsafe { std::slice::from_raw_parts(address as *const u8, guard.len()) };
    if actual != guard {
        return Err(format!(
            "{name} does not match the build this bridge was mapped against (RVA \
             0x{rva:X}). PIE control is disabled rather than calling it."
        ));
    }
    Ok(address)
}

unsafe fn read_u32(object: *mut c_void, offset: usize) -> u32 {
    *((object as *const u8).add(offset) as *const u32)
}

unsafe fn read_i32(object: *mut c_void, offset: usize) -> i32 {
    *((object as *const u8).add(offset) as *const i32)
}

unsafe fn read_f32(object: *mut c_void, offset: usize) -> f32 {
    *((object as *const u8).add(offset) as *const f32)
}

/// The play world, or null when PIE is not running.
///
/// Read through the same guard the control paths use. A status call that
/// answered from an unverified offset would be worse than one that refuses:
/// it would report "PIE is not running" from whatever happened to be at
/// `+0xAD0`, and every later decision would be built on that.
fn play_world(editor: *mut c_void) -> Result<*mut c_void, String> {
    guarded(PLAY_MAP_RVA, PLAY_MAP_GUARD, "UEditorEngine::PlayMap")?;
    Ok(unsafe { read_pointer(editor, PLAY_WORLD_OFFSET) })
}

pub(super) fn status(editor: *mut c_void) -> Result<String, String> {
    let world = play_world(editor)?;
    let flags = unsafe { read_u32(editor, PLAY_FLAGS_OFFSET) };
    let destination = unsafe { read_i32(editor, PLAY_WORLD_DESTINATION_OFFSET) };
    let viewport = unsafe { read_i32(editor, PLAY_IN_EDITOR_VIEWPORT_INDEX_OFFSET) };
    let active = !world.is_null();
    let queued = flags & FLAG_QUEUED != 0;

    let world_name = if active {
        super::unreal_object_string(world, true).unwrap_or_else(|_| String::new())
    } else {
        String::new()
    };

    let placement = if flags & FLAG_HAS_PLACEMENT != 0 {
        let location = unsafe {
            (
                read_f32(editor, PLAY_WORLD_LOCATION_OFFSET),
                read_f32(editor, PLAY_WORLD_LOCATION_OFFSET + 4),
                read_f32(editor, PLAY_WORLD_LOCATION_OFFSET + 8),
            )
        };
        // FRotator is integer UE3 units: 65536 to the turn, not degrees.
        let rotation = unsafe {
            (
                read_i32(editor, PLAY_WORLD_ROTATION_OFFSET),
                read_i32(editor, PLAY_WORLD_ROTATION_OFFSET + 4),
                read_i32(editor, PLAY_WORLD_ROTATION_OFFSET + 8),
            )
        };
        format!(
            r#","startLocation":{{"x":{:.3},"y":{:.3},"z":{:.3}}},"startRotation":{{"pitch":{},"yaw":{},"roll":{}}}"#,
            location.0, location.1, location.2, rotation.0, rotation.1, rotation.2
        )
    } else {
        String::new()
    };

    Ok(format!(
        r#"{{"pieActive":{active},"pieQueued":{queued},"playWorld":"{}","destination":{},"destinationIsThisEditor":{},"viewportIndex":{},"startInSpectatorMode":{},"hasStartPlacement":{},"mobilePreview":{},"movieCapture":{}{placement},"note":"{}"}}"#,
        super::json_escape(&world_name),
        destination,
        destination == DESTINATION_IN_EDITOR,
        viewport,
        flags & FLAG_SPECTATOR != 0,
        flags & FLAG_HAS_PLACEMENT != 0,
        flags & FLAG_MOBILE_PREVIEW != 0,
        flags & FLAG_MOVIE_CAPTURE != 0,
        super::json_escape(describe(active, queued)),
    ))
}

/// The sentence a caller actually needs, because the two booleans together mean
/// something neither means alone.
fn describe(active: bool, queued: bool) -> &'static str {
    match (active, queued) {
        (true, true) => "A play session is running and another start has been queued behind it.",
        (true, false) => {
            "A play session is running. Property reads and edits now see the play world's copy of \
             the map, not the map on disk, and edits made now are discarded when it ends."
        }
        (false, true) => {
            "A play session has been queued and will start on one of the next editor frames. It is \
             not running yet - poll this tool rather than assuming it started."
        }
        (false, false) => "No play session is running or queued. The editor world is the live one.",
    }
}

pub(super) fn start(editor: *mut c_void) -> Result<String, String> {
    let world = play_world(editor)?;
    if !world.is_null() {
        return Err("A play session is already running. Stop it before starting another; \
                    starting again would queue a second session behind the first."
            .to_string());
    }
    let flags = unsafe { read_u32(editor, PLAY_FLAGS_OFFSET) };
    if flags & FLAG_QUEUED != 0 {
        return Err("A play session is already queued and will start on one of the next editor \
                    frames. Poll renx_get_pie_status rather than queueing another."
            .to_string());
    }

    let address = guarded(PLAY_MAP_RVA, PLAY_MAP_GUARD, "UEditorEngine::PlayMap")?;
    let play_map: PlayMapFn = unsafe { std::mem::transmute::<usize, PlayMapFn>(address) };
    // Null placement means "use the map's own PlayerStart", which is what a
    // caller with no camera in hand wants. The two trailing flags are mobile
    // preview and movie capture: both off, because both change what is being
    // tested into something other than the map.
    unsafe {
        play_map(
            editor,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            DESTINATION_IN_EDITOR,
            VIEWPORT_STANDALONE,
            0,
            0,
        );
    }

    let queued = unsafe { read_u32(editor, PLAY_FLAGS_OFFSET) } & FLAG_QUEUED != 0;
    if !queued {
        return Err("The play request did not take: the editor's queued-play flag is still \
                    clear after the call. Nothing was started."
            .to_string());
    }
    Ok(format!(
        r#"{{"queued":true,"started":false,"note":"{}"}}"#,
        super::json_escape(
            "The play request is queued. The editor starts it on one of its own next frames - \
             this call deliberately does not wait, because waiting would hold the editor thread \
             inside a map load. Poll renx_get_pie_status until pieActive is true. If the user is \
             holding Ctrl at that moment the engine starts it in spectator mode, which \
             startInSpectatorMode will report."
        )
    ))
}

pub(super) fn stop(editor: *mut c_void) -> Result<String, String> {
    let world = play_world(editor)?;
    if world.is_null() {
        // Not an error worth failing loudly over, but it must not reach
        // EndPlayMap: `check(PlayWorld)` there is fatal in a release build.
        return Err("No play session is running, so there is nothing to stop. This is not a \
                    failure - renx_get_pie_status reports the same thing."
            .to_string());
    }

    let address = guarded(
        END_PLAY_MAP_RVA,
        END_PLAY_MAP_GUARD,
        "UEditorEngine::EndPlayMap",
    )?;
    let end_play_map: EndPlayMapFn = unsafe { std::mem::transmute::<usize, EndPlayMapFn>(address) };
    unsafe { end_play_map(editor) };

    let remaining = unsafe { read_pointer(editor, PLAY_WORLD_OFFSET) };
    if !remaining.is_null() {
        return Err("The editor still reports a play world after the teardown returned. The \
                    session may be partly torn down; ask the user to check the editor before \
                    relying on it."
            .to_string());
    }
    Ok(format!(
        r#"{{"stopped":true,"note":"{}"}}"#,
        super::json_escape(
            "The play session was torn down and the editor world is live again. Any change made \
             to actors during play is gone - that is UE3's behaviour, not this bridge's."
        )
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offsets were read out of `PlayMap`'s own stores, and they have to
    /// keep describing the struct UE3 declares: a pointer, then a packed
    /// `FVector`, then a packed `FRotator`, then the bitfield dword.
    #[test]
    fn the_member_offsets_form_the_declared_layout() {
        assert_eq!(PLAY_WORLD_OFFSET + 8, PLAY_WORLD_LOCATION_OFFSET);
        assert_eq!(PLAY_WORLD_LOCATION_OFFSET + 12, PLAY_WORLD_ROTATION_OFFSET);
        assert_eq!(PLAY_WORLD_ROTATION_OFFSET + 12, PLAY_FLAGS_OFFSET);
        assert_eq!(PLAY_FLAGS_OFFSET + 4, PLAY_WORLD_DESTINATION_OFFSET);
    }

    /// The guard has to reach past the entry point and cover the store this
    /// module reads back through, or it proves only that something is there.
    #[test]
    fn the_play_map_guard_covers_the_location_store() {
        let store = [0x89, 0x81, 0xD8, 0x0A, 0x00, 0x00];
        assert!(
            PLAY_MAP_GUARD
                .windows(store.len())
                .any(|window| window == store),
            "the guard no longer covers the PlayWorldLocation store"
        );
        // 0x0AD8 little-endian inside that store is the offset itself.
        let encoded = u32::from_le_bytes([0xD8, 0x0A, 0x00, 0x00]) as usize;
        assert_eq!(encoded, PLAY_WORLD_LOCATION_OFFSET);
    }

    #[test]
    fn the_flags_are_distinct_single_bits() {
        let flags = [
            FLAG_QUEUED,
            FLAG_SPECTATOR,
            FLAG_HAS_PLACEMENT,
            FLAG_MOBILE_PREVIEW,
            FLAG_MOVIE_CAPTURE,
        ];
        let mut seen = 0u32;
        for flag in flags {
            assert_eq!(flag.count_ones(), 1, "0x{flag:X} is not a single bit");
            assert_eq!(seen & flag, 0, "0x{flag:X} was already used");
            seen |= flag;
        }
        assert_eq!(seen, 0x1F);
    }

    /// Each combination has to say something different, because "queued" and
    /// "active" together are the case a caller most easily misreads.
    #[test]
    fn every_state_gets_its_own_sentence() {
        let all = [
            describe(false, false),
            describe(false, true),
            describe(true, false),
            describe(true, true),
        ];
        for (index, left) in all.iter().enumerate() {
            assert!(!left.is_empty());
            for right in all.iter().skip(index + 1) {
                assert_ne!(left, right);
            }
        }
        // The one that matters: queued is not running.
        assert!(describe(false, true).contains("not running yet"));
    }

    #[test]
    fn the_destination_sentinels_are_the_engine_s() {
        assert_eq!(DESTINATION_IN_EDITOR, -1);
        assert_eq!(VIEWPORT_STANDALONE, -1);
    }
}
