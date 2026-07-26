//! Guards `FUntypedBulkData::Serialize` (udk.exe+0x213C30) against a negative
//! or overflowing `ElementCount`, which otherwise reaches `appMemcpy` as a
//! negative byte count and kills a PC cook with an access violation.
//!
//! # The crash this fixes
//!
//! Diagnosed from `unreal-v12791-2026.07.25-22.38.20.dmp`: an
//! `EXCEPTION_ACCESS_VIOLATION` reading `0x00007FF1525CFFF8` inside
//! `msvcr100.dll+0x3C265` (`memcpy`), 72 bytes *below* the source buffer at
//! `R12 = 0x00007FF1525D0040`, with `RSI = RBX = 0xFFFFFFFF` (`-1`). The
//! symbolized stack:
//!
//! ```text
//! UObject::SavePackage            +0x4EE2   Export.Object->Serialize(*Linker)
//!   UTexture::Serialize            0x4DBC10  SourceArt.Serialize(Ar, this, INDEX_NONE)
//!   FUntypedBulkData::Serialize    0x213C30
//!   FUntypedBulkData::SerializeBulkData 0x204090
//!   FArchive::Serialize            0x19F371  appMemcpy(&Buffer[Count], src, -1)
//!   msvcr100!memcpy               +0x3C265  <- access violation
//! ```
//!
//! `SerializeBulkData` computes the byte count with a plain signed 32-bit
//! multiply and no sanity check at all:
//!
//! ```asm
//! 140204152  MOV  EBX, dword ptr [RDI + 0xc]   ; this->ElementCount  == -1
//! 140204155  MOV  RAX, qword ptr [RDI]         ; vtable
//! 14020415b  CALL qword ptr [RAX + 0x10]       ; virtual GetElementSize()
//! 14020415e  IMUL EAX, EBX                     ; ElementCount * ElementSize -> -1
//! 140204165  MOV  R8D, EAX                     ; length argument
//! 14020416e  CALL qword ptr [R9 + 0x8]         ; Ar.Serialize( Data, -1 )
//! ```
//!
//! # Why the hook goes on `Serialize` and not `SerializeBulkData`
//!
//! `ElementCount` is written to disk *before* the payload. In
//! `FUntypedBulkData::Serialize`'s load path:
//!
//! ```asm
//! 140213c64  LEA  RDX, [RSI + 0xc]             ; &ElementCount
//! 140213c71  CALL FUN_140151090                ; Ar.Serialize( &ElementCount, 4 )
//! ...
//! 140213c92  IMUL EAX, EBX                     ; second unchecked ElementCount * ElementSize
//! 140213c97  CALL FUN_1401caf90                ; appRealloc( BulkData, size, 8 )
//! ```
//!
//! so clamping inside `SerializeBulkData` would leave a header claiming
//! `-1` elements followed by a zero-byte payload. On load that header feeds
//! the second `IMUL` above into `appRealloc`, whose count parameter is a
//! `DWORD` - `-1` becomes a ~4 GB allocation request. Clamping at the entry
//! to `Serialize` instead means the header, the payload and the
//! `BulkDataSizeOnDisk` that the caller recomputes from `Ar.Tell()`
//! afterwards (udk.exe+0x213F43..0x213F51) all agree on zero.
//!
//! The clamp is deliberately direction-agnostic: a negative `ElementCount` is
//! never valid, and guarding both paths also defuses the load-side
//! `appRealloc` above.
//!
//! # Why this only bites PC cooks
//!
//! The offending field is `UTexture::SourceArt`, which is editor-only data.
//! `PLATFORM_FilterEditorOnly = PLATFORM_Console|PLATFORM_WindowsServer`
//! (`Core/Inc/UnFile.h`), so a `PCServer` cook strips source art and never
//! serializes it, while a `PC` cook keeps it (`Texture.cpp`:
//! `SourceArt.Serialize( Ar, this );`) and walks straight into the bad field.
//!
//! # Scope
//!
//! This is a containment fix, not a root-cause fix: it stops the cook dying
//! and names the offending object in the cook log, but the affected object's
//! bulk data is written empty. Anything reported here should be investigated
//! upstream - a texture whose `SourceArt` element count is `INDEX_NONE` got
//! into that state somehow, and suppressing the symptom at save time does not
//! undo it.
use crate::dll::{get_udk_ptr, UDK_RANGE};
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
use crate::udk_log;
use anyhow::Context;
use retour::static_detour;
use std::ffi::c_void;

/// Known static offset of `FUntypedBulkData::Serialize` in the 12791
/// (UDK-2015-01, CL 2424394) x64 build.
#[cfg(target_arch = "x86_64")]
const BULK_DATA_SERIALIZE_OFFSET: usize = 0x0021_3C30;

/// Prologue of `FUntypedBulkData::Serialize`, through the moves that stash its
/// five arguments:
///
/// ```asm
/// PUSH RBX; PUSH RSI; PUSH RDI; PUSH R12; PUSH R13
/// SUB  RSP, 0x20
/// CMP  dword ptr [RDX + 0x1c], 0x0      ; Ar.IsLoading()
/// MOV  R13D, R9D                        ; Idx
/// MOV  R12, R8                          ; Owner
/// MOV  RDI, RDX                         ; Ar
/// MOV  RSI, RCX                         ; this
/// ```
///
/// Verified unique in the 12791 x64 image (exactly one match).
#[cfg(target_arch = "x86_64")]
const BULK_DATA_SERIALIZE_SIG: [u8; 28] = [
    0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x48, 0x83, 0xEC, 0x20, 0x83, 0x7A, 0x1C, 0x00,
    0x45, 0x8B, 0xE9, 0x4D, 0x8B, 0xE0, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xF1,
];

/// `FUntypedBulkData::BulkDataFlags`, confirmed by `TEST byte ptr [RCX+0x8], 0x20`
/// at the top of `SerializeBulkData`.
const BULK_DATA_FLAGS_OFFSET: usize = 0x08;

/// `FUntypedBulkData::ElementCount`, confirmed by `MOV EBX, dword ptr [RDI+0xc]`
/// feeding the `IMUL` in `SerializeBulkData`.
const ELEMENT_COUNT_OFFSET: usize = 0x0C;

/// Vtable slot of `FUntypedBulkData::GetElementSize()`, confirmed by
/// `MOV RAX,[RDI]; CALL qword ptr [RAX+0x10]`.
const GET_ELEMENT_SIZE_VTABLE_OFFSET: usize = 0x10;

/// `UObject::GetFullName`, used only on the failure path to name the culprit.
/// Same RVA the MCP module uses; both resolve to a real function entry.
#[cfg(target_arch = "x86_64")]
const UOBJECT_GET_FULL_NAME_RVA: usize = 0x0026_8A30;

/// `appFree`, to release the `FString` `GetFullName` hands back.
#[cfg(target_arch = "x86_64")]
const APP_FREE_RVA: usize = 0x001C_AFE0;

type GetElementSizeFn = unsafe extern "C" fn(*mut c_void) -> i32;
type UObjectGetFullNameFn =
    unsafe extern "C" fn(*mut c_void, *mut UnrealString, *mut c_void) -> *mut UnrealString;
type AppFreeFn = unsafe extern "C" fn(*mut c_void);

/// UE3 `FString` (a `TArray<TCHAR>`).
#[repr(C)]
struct UnrealString {
    data: *mut u16,
    len: i32,
    capacity: i32,
}

static_detour! {
    static BulkDataSerializeHook: extern "C" fn(*mut c_void, *mut c_void, *mut c_void, i32, i32);
}

#[cfg(target_arch = "x86_64")]
fn find_bulk_data_serialize_offset() -> Option<usize> {
    let (best, count) =
        find_signature_offset(&BULK_DATA_SERIALIZE_SIG, BULK_DATA_SERIALIZE_OFFSET, 0);
    debug_log!("FUntypedBulkData::Serialize signature matches: {count}");
    best
}

/// Resolves `rva` to an address inside the loaded image, or `None` if it would
/// fall outside it.
#[cfg(target_arch = "x86_64")]
fn image_address(rva: usize) -> Option<usize> {
    let range = UDK_RANGE.get()?;
    let address = range.start.checked_add(rva)?;
    (address < range.end).then_some(address)
}

/// Calls the bulk data's virtual `GetElementSize()`.
fn element_size_of(bulk_data: *mut c_void) -> i32 {
    unsafe {
        let vtable = (bulk_data as *const *const u8).read();
        if vtable.is_null() {
            return 0;
        }
        let slot = vtable.add(GET_ELEMENT_SIZE_VTABLE_OFFSET) as *const GetElementSizeFn;
        (slot.read())(bulk_data)
    }
}

/// Best-effort `UObject::GetFullName` for the bulk data's owner, so the log
/// line names the asset. Only called on the failure path.
#[cfg(target_arch = "x86_64")]
fn owner_full_name(owner: *mut c_void) -> String {
    if owner.is_null() {
        return String::from("<null owner>");
    }

    let Some(get_full_name) = image_address(UOBJECT_GET_FULL_NAME_RVA) else {
        return String::from("<unresolved>");
    };

    let mut value = UnrealString {
        data: std::ptr::null_mut(),
        len: 0,
        capacity: 0,
    };

    unsafe {
        let function: UObjectGetFullNameFn = std::mem::transmute(get_full_name);
        function(owner, &mut value, std::ptr::null_mut());
    }

    let name = if value.data.is_null() || value.len <= 0 {
        String::from("<empty>")
    } else {
        let units = unsafe { std::slice::from_raw_parts(value.data, value.len as usize) };
        let end = units.iter().position(|unit| *unit == 0).unwrap_or(units.len());
        String::from_utf16_lossy(&units[..end])
    };

    if !value.data.is_null() {
        if let Some(app_free) = image_address(APP_FREE_RVA) {
            unsafe {
                let free: AppFreeFn = std::mem::transmute(app_free);
                free(value.data.cast());
            }
        }
    }

    name
}

#[cfg(not(target_arch = "x86_64"))]
fn owner_full_name(_owner: *mut c_void) -> String {
    String::from("<unavailable>")
}

/// Hook for `FUntypedBulkData::Serialize(FArchive&, UObject* Owner, INT Idx, UBOOL bAttemptFileMapping)`.
///
/// Clamps an invalid `ElementCount` to zero before the original runs, so the
/// serialized header, payload and recomputed on-disk size stay consistent, and
/// reports the owning object through the UDK log so it lands in the cook log
/// next to the package being written.
fn bulk_data_serialize_hook(
    bulk_data: *mut c_void,
    archive: *mut c_void,
    owner: *mut c_void,
    index: i32,
    attempt_file_mapping: i32,
) {
    if !bulk_data.is_null() {
        let count_ptr = unsafe { (bulk_data as *mut u8).add(ELEMENT_COUNT_OFFSET) as *mut i32 };
        let count = unsafe { count_ptr.read_unaligned() };
        let element_size = element_size_of(bulk_data);
        let bytes = (count as i64).saturating_mul(element_size as i64);

        if count < 0 || bytes > i32::MAX as i64 {
            let flags = unsafe {
                ((bulk_data as *const u8).add(BULK_DATA_FLAGS_OFFSET) as *const u32).read_unaligned()
            };

            udk_log::log(
                udk_log::LogType::Warning,
                &format!(
                    "invalid bulk data on '{}': ElementCount={count} ElementSize={element_size} \
                     ({bytes} bytes) BulkDataFlags=0x{flags:08X} Idx={index}. Clamping ElementCount \
                     to 0 so FUntypedBulkData does not hand a bad length to appMemcpy/appRealloc. \
                     This object's bulk data will be EMPTY in the cooked package - investigate the asset.",
                    owner_full_name(owner)
                ),
            );

            unsafe { count_ptr.write_unaligned(0) };
        }
    }

    BulkDataSerializeHook.call(bulk_data, archive, owner, index, attempt_file_mapping);
}

pub fn init() -> anyhow::Result<()> {
    debug_log!("udk_bulk_data_count::init start");

    #[cfg(target_arch = "x86_64")]
    {
        let udk = get_udk_ptr();

        let offset = find_bulk_data_serialize_offset()
            .context("Failed to find FUntypedBulkData::Serialize signature")?;

        debug_log!("FUntypedBulkData::Serialize hook offset selected: 0x{offset:X}");

        unsafe {
            BulkDataSerializeHook
                .initialize(
                    std::mem::transmute(udk.add(offset)),
                    bulk_data_serialize_hook,
                )
                .context("Failed to setup FUntypedBulkData::Serialize hook")?;

            BulkDataSerializeHook.enable()?;
        }

        debug_log!("udk_bulk_data_count: hook installed successfully");
    }

    debug_log!("udk_bulk_data_count::init done");

    Ok(())
}
