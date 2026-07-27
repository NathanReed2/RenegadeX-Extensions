//! Makes `-platform=PCServer` produce cooked script packages a
//! `-seekfreeloadingserver` dedicated server can actually load.
//!
//! Two independent defects sit between a PCServer cook and a working server;
//! both are one- or two-byte immediate edits.
//!
//! # Prerequisite outside this patch
//!
//! Neither patch matters unless `UDKGame\Config\PCServer\PCServerEngine.ini`
//! exists. `GeneratePackageList` reads the script package lists from the
//! platform ini named by `UpdateCookedPlatformIniFilesFromDefaults`
//! (`Config\<Platform>\<Platform>Engine.ini` -> generated
//! `Config\<Platform>\Cooked\<Platform>-<Game>Engine.ini`). If that default is
//! missing, the generated ini has no `[Engine.ScriptPackages]`, so
//! `NativeScriptPackageNames` comes back empty and no package ever matches
//! `bIsNativeScriptFile` - the cook silently emits no script at all.
//! `PLATFORM_Windows` sidesteps this because the cooker uses `GEngineIni`
//! directly for it. A two-line
//! `[Configuration] BasedOn=..\UDKGame\Config\DefaultEngine.ini` is enough.
//!
//! # Patch 1: cooked script filename
//!
//! `UCookPackagesCommandlet::GetCookedPackageFilename`
//! (`UnrealEd/Src/UnContentCookers.cpp`):
//!
//! ```c
//! else if( Platform == PLATFORM_Windows || Platform == PLATFORM_MacOSX )
//! {
//!     // ... walk past appEngineDir()/appGameDir() and the first subdirectory,
//!     // then keep the rest of the source path *and its extension* verbatim
//!     DstFilename = CookedDir + AfterTopLevelDir;
//! }
//! else
//! {
//!     // flatten to the base name and force the platform's content extension
//!     DstFilename = CookedDir + SrcFilename.GetBaseFilename() + GetCookedPackageExtension(Platform);
//! }
//! ```
//!
//! `PLATFORM_WindowsServer` is not in that list, so a PCServer cook takes the
//! `else` branch for *every* package, script included.
//! `GetCookedPackageExtension` returns `.upk` for it (the `.xxx` console
//! extension is selected by the `Platform & PLATFORM_Console` mask, which does
//! not cover `PLATFORM_WindowsServer`), so `..\..\UDKGame\Script\Engine.u` is
//! cooked to `CookedPCServer\Engine.upk` - the same path as the seekfree
//! *content* package `Engine`. The cooker writes both halves to one file and the
//! last writer wins, so cooked script is silently replaced by cooked content.
//!
//! The compiled branch (`this + 0xC4` is the commandlet's `Platform`):
//!
//! ```asm
//! MOV  R8D, dword ptr [RCX + 0xC4]   ; this->Platform
//! CMP  R8D, 1                        ; PLATFORM_Windows
//! JZ   LAB_preserve                  ; -> keep source path + extension
//! CMP  R8D, 0x20                     ; PLATFORM_MacOSX
//! JZ   LAB_preserve                  ; -> same target
//! ...                                ; flatten + force platform extension
//! ```
//!
//! Rewriting the first comparison to `CMP R8D, 2` / `JBE` makes the range
//! `0..=2` take the preserving branch, adding `PLATFORM_WindowsServer` (2) while
//! leaving `PLATFORM_Windows` (1) exactly as it was. `PLATFORM_Unknown` (0) is
//! also swept in, but a cook never reaches here with it - the commandlet rejects
//! an unparsed platform up front ("Unknown platform (%s) specified").
//! `PLATFORM_MacOSX` keeps its own comparison, now only reached when the first
//! falls through.
//!
//! Both edits are same-length and in place: the `imm8` of the `CMP`, and the
//! second opcode byte of the two-byte `0F 8x rel32` jump (`JZ` `0x84` -> `JBE`
//! `0x86`). The `rel32` displacement is untouched, so both conditional jumps
//! keep pointing at the same label.
//!
//! # Patch 2: `UClass::Serialize` writes fewer fields than it reads
//!
//! With the filenames fixed the cook produces real `.u` files that the server
//! still cannot load - it dies in `FLinkerLoad` with
//! `appError: Bad name index -1/822` before the `ServerCommandlet` starts.
//!
//! `UClass::Serialize` (`Core/Src/UnClass.cpp`) guards a block of editor-only
//! fields:
//!
//! ```c
//! UBOOL const bIsCookedForConsole  = IsPackageCookedForConsole(Ar);
//! UBOOL const bIsCookedForPCServer = Ar.GetLinker()
//!     && (Ar.GetLinker()->LinkerRoot->PackageFlags & PKG_Cooked)
//!     && (GPatchingTarget & UE3::PLATFORM_WindowsServer);
//! UBOOL const bCookingConsoleOrPCServer =
//!     (GCookingTarget & (UE3::PLATFORM_Console|UE3::PLATFORM_WindowsServer)) != 0;
//!
//! if ( !bIsCookedForConsole && !bIsCookedForPCServer &&
//!     (!bCookingConsoleOrPCServer || !Ar.IsSaving() || Ar.GetLinker() == NULL) )
//! {
//!     if( Ar.Ver() >= VER_DONTSORTCATEGORIES_ADDED ) { Ar << DontSortCategories; }
//!     Ar << HideCategories << AutoExpandCategories << AutoCollapseCategories;
//!     if( Ar.Ver() >= VER_FORCE_SCRIPT_DEFINED_ORDER_PER_CLASS ) { Ar << bForceScriptOrder; }
//!     if( Ar.Ver() >= VER_ADDED_CLASS_GROUPS ) { Ar << ClassGroupNames; }
//!     Ar << ClassHeaderFilename;
//! }
//! ```
//!
//! The write side and the read side test **different globals**:
//!
//! | | writing (cook) | reading (server load) |
//! |---|---|---|
//! | guard | `GCookingTarget & (Console\|WindowsServer)` | `GPatchingTarget & WindowsServer` |
//! | PCServer value | `PLATFORM_WindowsServer` -> skips | `PLATFORM_Unknown` -> reads |
//!
//! `GPatchingTarget` is `PLATFORM_Unknown` (`Core/Src/Core.cpp`) and is only
//! assigned while the *script patcher* runs, never by a dedicated server. So a
//! PCServer cook skips writing all seven fields, and every non-console loader
//! reads them back: seven `TArray`/`FString`/`UBOOL` fields, 4 bytes each when
//! empty, so each `UClass` export is 28 bytes short of what the loader consumes.
//! The archive desynchronises inside the first class and the next `FName` read
//! comes back as `INDEX_NONE`, which is the reported `-1`.
//!
//! Console cooks never hit this because console builds compile the whole block
//! out (`#if !CONSOLE` / `#else` in the same function), so nothing writes *or*
//! reads it there. `-platform=PC` never hits it either: `PLATFORM_Windows` is in
//! neither mask, so PC cooks write the fields and PC loads read them. PCServer is
//! the one configuration where the same non-console binary writes with one rule
//! and reads with the other.
//!
//! The fix makes the cook agree with the loader by dropping
//! `PLATFORM_WindowsServer` from the *write-side* mask only, so a PCServer cook
//! emits exactly the byte layout a `-platform=PC` cook does - the layout this
//! engine build is known to load:
//!
//! ```asm
//! TEST ebx, ebx                                  ; bIsCookedForConsole
//! JNE  LAB_skip
//! TEST edi, edi                                  ; bIsCookedForPCServer
//! JNE  LAB_skip
//! TEST dword ptr [GCookingTarget], 0xF8E         ; Console|WindowsServer
//! JZ   LAB_serialize
//! CMP  dword ptr [RSI + 0x18], edi               ; Ar.IsSaving()
//! ...
//! ```
//!
//! Clearing bit 1 of that `imm32` (`0xF8E` -> `0xF8C`, i.e. `PLATFORM_Console`
//! alone) is a one-byte edit. Console cooking is unaffected - every
//! `PLATFORM_Console` bit is kept - and the read side is unaffected too, because
//! at load time this same test is already reached with `GCookingTarget` clear.
//!
//! The cost is 28 bytes per class in cooked server script, which is what the
//! working reference data set contains anyway.
//!
//! # Patch 3: editor-only filtering must not apply to cooked script
//!
//! `PLATFORM_WindowsServer` is a member of the editor-only filter mask
//! (`Core/Inc/UnFile.h`):
//!
//! ```c
//! PLATFORM_FilterEditorOnly = PLATFORM_Console|PLATFORM_WindowsServer,
//! ```
//!
//! so the cooker stamps every package it saves for PCServer, script included
//! (`UnrealEd/Src/UnContentCookers.cpp`):
//!
//! ```c
//! Package->PackageFlags |= (GCookingTarget & PLATFORM_FilterEditorOnly) != 0 ? PKG_FilterEditorOnly : 0;
//! ```
//!
//! For *content* that is fine - it skips editor-only property values, and the
//! loader re-derives the same decision from the flag in the header, so both sides
//! agree. For *script* it is not, because the flag does more than skip values: it
//! drops editor-only `UProperty` **objects** from the class being saved.
//! `UProperty::Serialize` asserts exactly that (`Core/Src/UnProp.cpp`):
//!
//! ```c
//! check( !Ar.IsFilterEditorOnly() || !IsEditorOnlyProperty() );
//! ```
//!
//! A cooked-for-PCServer `Engine.u` therefore has ~2000 fewer exports than the
//! `-platform=PC` one built from the same sources, and the classes it defines are
//! missing members. Consoles survive this because a console build is compiled
//! with `WITH_EDITORONLY_DATA` off, so its native C++ layout has no editor-only
//! members either and the two match. A PCServer cook is loaded by *this* binary,
//! which is compiled *with* them - so the class described by the cooked script no
//! longer matches the natively compiled layout, and property data deserialised
//! into a class default object lands on native fields. In practice
//! `UMaterial::PostLoad` then walks `MaterialResources[]` and finds two packed
//! 32-bit property values where a pointer should be, and the server dies with a
//! `0xC0000005` write to that address while loading startup packages.
//!
//! There is no per-package hook to key off in the compiled code, so this patch
//! removes `PLATFORM_WindowsServer` from the mask, leaving the flag off for
//! everything in a PCServer cook. Cooked server *content* therefore keeps its
//! editor-only property values - larger on disk than strictly necessary, and
//! exactly the shape a `-platform=PC` cook produces, which this engine loads
//! happily. Console cooks are untouched: the mask keeps every `PLATFORM_Console`
//! bit.
//!
//! ```asm
//! MOV  EAX, dword ptr [GCookingTarget]
//! AND  EAX, 0xF8E                    ; PLATFORM_Console|PLATFORM_WindowsServer
//! NEG  EAX                           ; \
//! SBB  EAX, EAX                      ;  | (mask != 0) ? 0xFFFFFFFF : 0
//! MOV  ECX, 0x80000000               ; PKG_FilterEditorOnly
//! AND  EAX, ECX                      ; /
//! ```
//!
//! Clearing bit 1 of that `imm32` (`0xF8E` -> `0xF8C`) is a one-byte edit.
//!
//! # Patch 4: non-native (mod) script is never emitted
//!
//! With patches 1-3 the cook produces loadable native script and the server
//! reaches `Executing Class Engine.ServerCommandlet`, then fails with
//! `Failed to find object 'Class RenX_Game.Rx_GameEngine'`. The game's own script
//! packages are gathered (`appGetScriptPackageNames(..., SPT_NonNative, ...)`
//! picks them up from `[UnrealEd.EditorEngine] ModEditPackages`) and are loaded
//! and cooked - the log shows `Cooking RenX_Game` - but they are never added to
//! the list of packages to write, because of one more `PLATFORM_Windows`-only
//! gate in `UCookPackagesCommandlet::GeneratePackageList`
//! (`UnrealEd/Src/UnContentCookers.cpp`):
//!
//! ```c
//! // Package is a non-native script file
//! else if (bIsNonNativeScriptFile && (GCookingTarget == PLATFORM_Windows))
//! {
//!     ScriptFilenamePairs.AddItem( FPackageCookerInfo( *SrcFilename, *DstFilename, FALSE, FALSE, FALSE, FALSE, TRUE ) );
//! }
//! ```
//!
//! An exact equality against `PLATFORM_Windows`, so for PCServer the branch is
//! skipped and the cooked mod script is silently discarded. (Consoles put their
//! non-native script in the combined `Startup.xxx` instead, which is why they do
//! not need this branch.)
//!
//! ```asm
//! CMP  dword ptr [RBP - 0x28], 0     ; bIsNonNativeScriptFile
//! JZ   LAB_skip
//! CMP  dword ptr [GCookingTarget], 1 ; PLATFORM_Windows
//! JNZ  LAB_skip
//! ...                                ; ScriptFilenamePairs.AddItem(...)
//! ```
//!
//! There is a second gate on the same list further down the same function, where
//! the collected pairs are ordered into the final cook list. Only names present
//! in `ScriptPackageNames` survive the match at the bottom, and the non-native
//! ones are only added to it for `PLATFORM_Windows`:
//!
//! ```c
//! TArray<FString> ScriptPackageNames;
//! ScriptPackageNames += NativeScriptPackageNames;
//!
//! if (GCookingTarget == PLATFORM_Windows)
//! {
//!     for (INT GameScriptIndex = 0; GameScriptIndex < NonNativeScriptPackageNames.Num(); GameScriptIndex++)
//!     {
//!         ScriptPackageNames.AddUniqueItem(NonNativeScriptPackageNames(GameScriptIndex));
//!     }
//! }
//! for( INT NameIndex=0; ... )          // only these get appended to the cook list
//! ```
//!
//! Patching only the first gate makes things *worse*, not better: the package
//! moves out of whatever list was previously loading it into `ScriptFilenamePairs`
//! and is then dropped here, so it stops being cooked at all. Both have to go
//! together.
//!
//! ```asm
//! CMP  dword ptr [GCookingTarget], 1 ; PLATFORM_Windows
//! JNZ  LAB_skip
//! MOV  EDI, EBX                      ; GameScriptIndex = 0
//! MOV  EAX, dword ptr [RBP + 0x40]   ; NonNativeScriptPackageNames.Num()
//! TEST EAX, EAX
//! ```
//!
//! Same rewrite as patch 1 at both sites: `CMP ..., 2` / `JA` accepts the range
//! `0..=2`, adding `PLATFORM_WindowsServer` (2) and leaving `PLATFORM_Windows` (1)
//! as it was. Every edit is a same-length in-place immediate - the `imm8` of the
//! `CMP` and the opcode of the `rel8` conditional jump (`JNZ` `0x75` -> `JA`
//! `0x77`), so the displacements still point at the same labels.
//!
//! # Patch 5: cooked content keeps only textures
//!
//! With patches 1-4 the server loads all script and reaches
//! `Initializing Game Engine...`, then dies with
//! `appError: Failed to load special material 'EngineMaterials.DefaultDecalMaterial'`.
//! A PCServer-cooked `EngineMaterials.upk` is 9 KB where the `-platform=PC` one
//! built from the same content is 237 KB, because
//! `UCookPackagesCommandlet::SaveCookedPackage` strips every non-texture object
//! out of the packages cooked ahead of script
//! (`UnrealEd/Src/UnContentCookers.cpp`):
//!
//! ```c
//! // for PC and Mac we don't strip out non-texture objects
//! UBOOL bStripEverythingButTextures = (PackageIndex < FirstScriptIndex)
//!     && (Platform != PLATFORM_Windows) && (Platform != PLATFORM_MacOSX);
//! ...
//! // for PC cooking, we leave all objects in their original packages, and in cooked packages
//! if (Platform == PLATFORM_Windows)
//! {
//!     bStripEverythingButTextures = FALSE;
//!
//!     // make sure destination exists
//!     GFileManager->MakeDirectory(*FFilename(DstFilename).GetPath(), TRUE);
//!
//!     for( TObjectIterator<UObject> It; It; ++It )
//!     {
//!         // never allow any shader objects to get cooked into another package
//!         if (It->IsA(UShaderCache::StaticClass())) { It->ClearFlags( RF_ForceTagExp ); }
//!     }
//! }
//! ```
//!
//! On a console that is harmless: those packages exist only to carry texture
//! mips, and the objects themselves are re-cooked into the combined
//! `Startup.xxx`. A PCServer cook builds no combined startup package
//! (`[Engine.StartupPackages]` is empty in the generated platform ini), so the
//! stripped objects simply cease to exist and the engine cannot resolve the
//! special materials named in `[Engine.Engine]`.
//!
//! Widening the `PLATFORM_Windows` test is the right fix rather than just forcing
//! the flag, because all three things the block does are wanted for a dedicated
//! server: keep the non-texture objects, create the destination directory (patch
//! 1 gives PCServer the same nested output paths PC uses, so this is now load
//! bearing), and keep shader caches from being dragged into other packages. It
//! also subsumes the `bStripEverythingButTextures` expression above, which is
//! only read after this block.
//!
//! ```asm
//! CMP  dword ptr [R13 + 0xC4], 1     ; this->Platform == PLATFORM_Windows
//! JNZ  LAB_skip
//! MOV  dword ptr [RBP + 8], 0        ; bStripEverythingButTextures = FALSE
//! ```
//!
//! Same rewrite again: `CMP ..., 2` / `JA`. Here the jump is a `rel32`, so the
//! edited byte is the second of its two opcode bytes (`0F 85` -> `0F 87`).
//!
//! # What is deliberately *not* patched
//!
//! A PCServer cook still drops each class's `ScriptText`/`CppText`
//! (`UTextBuffer`, the `.uc` source text) and the package's `MetaData` object
//! (tooltips, property ordering). That is correct: those are pure editor data, a
//! dedicated server has no use for them, and the references are written as plain
//! `NULL` rather than skipped, so nothing desynchronises. It only means a cooked
//! server `Core.u` has slightly fewer names than a cooked PC one.
use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
use anyhow::Context;

/// Known offset (from the `udk.exe` module base) of the `MOV R8D,[RCX+0xC4]`
/// that begins the platform test, taken from the 12791 (UDK-2015-01,
/// CL 2424394) x64 build. Used only to pick the nearest match if the signature
/// scan below ever finds more than one hit.
#[cfg(target_arch = "x86_64")]
const COOKED_FILENAME_PLATFORM_TEST_OFFSET: usize = 0x011B_11E5;

/// Signature covering the whole first comparison:
/// `MOV R8D,[RCX+0xC4]; CMP R8D,1; JZ rel32`.
///
/// Verified unique in the 12791 x64 image (exactly one match).
#[cfg(target_arch = "x86_64")]
const COOKED_FILENAME_PLATFORM_SIG: [u8; 17] = [
    0x44, 0x8B, 0x81, 0xC4, 0x00, 0x00, 0x00, // MOV R8D, dword ptr [RCX + 0xC4]
    0x41, 0x83, 0xF8, 0x01, // CMP R8D, 1
    0x0F, 0x84, 0xC8, 0x00, 0x00, 0x00, // JZ LAB_preserve
];

/// Offset of the `CMP` immediate within [`COOKED_FILENAME_PLATFORM_SIG`].
#[cfg(target_arch = "x86_64")]
const SIG_CMP_IMMEDIATE_SKEW: usize = 10;

/// Offset of the jump's second opcode byte within
/// [`COOKED_FILENAME_PLATFORM_SIG`].
#[cfg(target_arch = "x86_64")]
const SIG_JUMP_OPCODE_SKEW: usize = 12;

/// `PLATFORM_WindowsServer`, the highest platform value that should reach the
/// path-preserving branch once the comparison becomes `JBE`.
#[cfg(target_arch = "x86_64")]
const PLATFORM_WINDOWS_SERVER: u8 = 2;

/// Second opcode byte of `JBE rel32`, replacing `JZ rel32`'s `0x84`.
#[cfg(target_arch = "x86_64")]
const JBE_REL32_OPCODE: u8 = 0x86;

/// Known offset (from the `udk.exe` module base) of the `TEST ebx,ebx` that
/// begins `UClass::Serialize`'s editor-only field guard, taken from the 12791
/// x64 build.
#[cfg(target_arch = "x86_64")]
const CLASS_SERIALIZE_GUARD_OFFSET: usize = 0x0021_5BFF;

/// Signature covering the guard up to (but not including) the RIP-relative
/// displacement of `GCookingTarget`, which is position dependent:
/// `TEST ebx,ebx; JNE rel32; TEST edi,edi; JNE rel32; TEST dword ptr [rip+?],`.
///
/// Anchoring on both preceding tests plus their `rel32` jumps is what makes this
/// unique - a bare `TEST dword ptr [rip+?], 0xF8E` is not, the same mask is
/// tested in several unrelated places.
///
/// Verified unique in the 12791 x64 image (exactly one match).
#[cfg(target_arch = "x86_64")]
const CLASS_SERIALIZE_GUARD_SIG: [u8; 18] = [
    0x85, 0xDB, // TEST ebx, ebx              (bIsCookedForConsole)
    0x0F, 0x85, 0xC1, 0x00, 0x00, 0x00, // JNE LAB_skip
    0x85, 0xFF, // TEST edi, edi              (bIsCookedForPCServer)
    0x0F, 0x85, 0xB9, 0x00, 0x00, 0x00, // JNE LAB_skip
    0xF7, 0x05, // TEST dword ptr [rip + GCookingTarget], imm32
];

/// Offset of the cooking-target mask's low byte within
/// [`CLASS_SERIALIZE_GUARD_SIG`]: the 18 signature bytes, then the 4-byte
/// RIP-relative displacement the signature stops short of.
#[cfg(target_arch = "x86_64")]
const SIG_COOKING_MASK_LOW_BYTE_SKEW: usize = CLASS_SERIALIZE_GUARD_SIG.len() + 4;

/// `PLATFORM_Console|PLATFORM_WindowsServer` (`0xF8E`) with
/// `PLATFORM_WindowsServer` (bit 1) cleared, i.e. the low byte of
/// `PLATFORM_Console` alone.
#[cfg(target_arch = "x86_64")]
const COOKING_MASK_WITHOUT_WINDOWS_SERVER: u8 = 0x8C;

/// Known offset (from the `udk.exe` module base) of the `AND EAX, 0xF8E` that
/// applies `PKG_FilterEditorOnly` to the package about to be saved, taken from
/// the 12791 x64 build.
#[cfg(target_arch = "x86_64")]
const FILTER_EDITOR_ONLY_MASK_OFFSET: usize = 0x011E_A743;

/// Signature covering the whole `(GCookingTarget & PLATFORM_FilterEditorOnly)
/// != 0 ? PKG_FilterEditorOnly : 0` computation, anchored on the
/// `PKG_FilterEditorOnly` constant so it cannot match an unrelated use of the
/// same platform mask:
/// `AND EAX,0xF8E; NEG EAX; SBB EAX,EAX; MOV ECX,0x80000000; AND EAX,ECX`.
///
/// Verified unique in the 12791 x64 image (exactly one match).
#[cfg(target_arch = "x86_64")]
const FILTER_EDITOR_ONLY_SIG: [u8; 16] = [
    0x25, 0x8E, 0x0F, 0x00, 0x00, // AND EAX, 0xF8E
    0xF7, 0xD8, // NEG EAX
    0x1B, 0xC0, // SBB EAX, EAX
    0xB9, 0x00, 0x00, 0x00, 0x80, // MOV ECX, 0x80000000 (PKG_FilterEditorOnly)
    0x23, 0xC1, // AND EAX, ECX
];

/// Offset of the mask's low byte within [`FILTER_EDITOR_ONLY_SIG`].
#[cfg(target_arch = "x86_64")]
const SIG_FILTER_MASK_LOW_BYTE_SKEW: usize = 1;

/// Known offset (from the `udk.exe` module base) of the
/// `CMP dword ptr [RBP-0x28], 0` that begins
/// `bIsNonNativeScriptFile && (GCookingTarget == PLATFORM_Windows)` in
/// `GeneratePackageList`, taken from the 12791 x64 build.
#[cfg(target_arch = "x86_64")]
const NON_NATIVE_SCRIPT_TEST_OFFSET: usize = 0x011F_6226;

/// Signature covering the guard up to (but not including) the RIP-relative
/// displacement of `GCookingTarget`, which is position dependent:
/// `CMP dword ptr [RBP-0x28],0; JZ rel8; CMP dword ptr [rip+?],`.
///
/// Verified unique in the 12791 x64 image (exactly one match).
#[cfg(target_arch = "x86_64")]
const NON_NATIVE_SCRIPT_SIG: [u8; 8] = [
    0x83, 0x7D, 0xD8, 0x00, // CMP dword ptr [RBP - 0x28], 0   (bIsNonNativeScriptFile)
    0x74, 0x61, // JZ LAB_skip
    0x83, 0x3D, // CMP dword ptr [rip + GCookingTarget], imm8
];

/// Offset of the `CMP`'s `imm8` within [`NON_NATIVE_SCRIPT_SIG`]: the 8
/// signature bytes, then the 4-byte RIP-relative displacement it stops short of.
#[cfg(target_arch = "x86_64")]
const SIG_NON_NATIVE_IMMEDIATE_SKEW: usize = NON_NATIVE_SCRIPT_SIG.len() + 4;

/// Offset of the following `rel8` jump's opcode.
#[cfg(target_arch = "x86_64")]
const SIG_NON_NATIVE_JUMP_OPCODE_SKEW: usize = SIG_NON_NATIVE_IMMEDIATE_SKEW + 1;

/// Opcode of `JA rel8`, replacing `JNZ rel8`'s `0x75` so the comparison becomes
/// "greater than `PLATFORM_WindowsServer`" instead of "not equal".
#[cfg(target_arch = "x86_64")]
const JA_REL8_OPCODE: u8 = 0x77;

/// Known offset (from the `udk.exe` module base) of the `imm8` of the second
/// `GCookingTarget == PLATFORM_Windows` gate, the one guarding
/// `ScriptPackageNames.AddUniqueItem(NonNativeScriptPackageNames(...))`, taken
/// from the 12791 x64 build.
#[cfg(target_arch = "x86_64")]
const NON_NATIVE_SORT_TEST_OFFSET: usize = 0x011F_68B0;

/// Signature starting *at* the `CMP`'s `imm8`, so the position-dependent
/// RIP-relative displacement in front of it is not part of the pattern:
/// `<imm8 01>; JNZ rel8; MOV EDI,EBX; MOV EAX,[RBP+0x40]; TEST EAX,EAX`.
///
/// Verified unique in the 12791 x64 image (exactly one match).
#[cfg(target_arch = "x86_64")]
const NON_NATIVE_SORT_SIG: [u8; 10] = [
    0x01, // imm8 of CMP dword ptr [rip + GCookingTarget], 1
    0x75, 0x5B, // JNZ LAB_skip
    0x8B, 0xFB, // MOV EDI, EBX                      (GameScriptIndex = 0)
    0x8B, 0x45, 0x40, // MOV EAX, [RBP + 0x40]       (NonNativeScriptPackageNames.Num())
    0x85, 0xC0, // TEST EAX, EAX
];

/// Known offset (from the `udk.exe` module base) of the
/// `CMP dword ptr [R13+0xC4], 1` that opens the PC-only branch of
/// `SaveCookedPackage`, taken from the 12791 x64 build.
#[cfg(target_arch = "x86_64")]
const SAVE_COOKED_PC_BRANCH_OFFSET: usize = 0x011E_96F4;

/// Signature covering the platform test and the first opcode byte of the jump
/// that skips the PC-only block:
/// `CMP dword ptr [R13+0xC4],1; JNZ rel32`.
///
/// Verified unique in the 12791 x64 image (exactly one match).
#[cfg(target_arch = "x86_64")]
const SAVE_COOKED_PC_BRANCH_SIG: [u8; 10] = [
    0x41, 0x83, 0xBD, 0xC4, 0x00, 0x00, 0x00, 0x01, // CMP dword ptr [R13 + 0xC4], 1
    0x0F, 0x85, // JNZ rel32 (skip the PC-only block)
];

/// Offset of the `CMP`'s `imm8` within [`SAVE_COOKED_PC_BRANCH_SIG`].
#[cfg(target_arch = "x86_64")]
const SIG_SAVE_COOKED_IMMEDIATE_SKEW: usize = 7;

/// Offset of the second opcode byte of the `rel32` jump within
/// [`SAVE_COOKED_PC_BRANCH_SIG`].
#[cfg(target_arch = "x86_64")]
const SIG_SAVE_COOKED_JUMP_OPCODE_SKEW: usize = 9;

/// Second opcode byte of `JA rel32`, replacing `JNZ rel32`'s `0x85`.
#[cfg(target_arch = "x86_64")]
const JA_REL32_OPCODE: u8 = 0x87;

/// Overwrites a single byte inside `udk.exe`'s image.
#[cfg(target_arch = "x86_64")]
unsafe fn write_byte(address: usize, value: u8, what: &'static str) -> anyhow::Result<()> {
    let pointer = address as *mut u8;

    let _guard = region::protect_with_handle(pointer, 1, region::Protection::READ_WRITE_EXECUTE)
        .with_context(|| format!("Failed to make {what} writable"))?;

    unsafe { std::ptr::write_volatile(pointer, value) };

    Ok(())
}

pub fn init() -> anyhow::Result<()> {
    debug_log!("udk_pcserver_script_cook::init start");

    #[cfg(target_arch = "x86_64")]
    {
        let range = UDK_RANGE.get().context("UDK_RANGE not set")?;

        let (filename_offset, filename_count) = find_signature_offset(
            &COOKED_FILENAME_PLATFORM_SIG,
            COOKED_FILENAME_PLATFORM_TEST_OFFSET,
            0,
        );
        debug_log!("pcserver-script-cook filename signature matches: {filename_count}");

        let filename_offset = filename_offset
            .context("Failed to find GetCookedPackageFilename platform test signature")?;
        let test_address = range.start.saturating_add(filename_offset);

        debug_log!(
            "udk_pcserver_script_cook: patching platform test at 0x{test_address:X} (sig offset 0x{filename_offset:X}) to CMP R8D,2 / JBE, so PCServer cooks keep script package paths and extensions"
        );

        unsafe {
            write_byte(
                test_address.saturating_add(SIG_CMP_IMMEDIATE_SKEW),
                PLATFORM_WINDOWS_SERVER,
                "the platform test immediate",
            )?;
            write_byte(
                test_address.saturating_add(SIG_JUMP_OPCODE_SKEW),
                JBE_REL32_OPCODE,
                "the platform test jump opcode",
            )?;
        }

        debug_log!("udk_pcserver_script_cook: filename patch applied successfully");

        let (guard_offset, guard_count) = find_signature_offset(
            &CLASS_SERIALIZE_GUARD_SIG,
            CLASS_SERIALIZE_GUARD_OFFSET,
            0,
        );
        debug_log!("pcserver-script-cook UClass::Serialize guard matches: {guard_count}");

        let guard_offset = guard_offset
            .context("Failed to find the UClass::Serialize editor-only guard signature")?;
        let mask_address = range
            .start
            .saturating_add(guard_offset)
            .saturating_add(SIG_COOKING_MASK_LOW_BYTE_SKEW);

        debug_log!(
            "udk_pcserver_script_cook: clearing PLATFORM_WindowsServer from UClass::Serialize's cooking-target mask at 0x{mask_address:X} (sig offset 0x{guard_offset:X}), so a PCServer cook writes the editor-only class fields every non-console loader reads back"
        );

        unsafe {
            write_byte(
                mask_address,
                COOKING_MASK_WITHOUT_WINDOWS_SERVER,
                "the UClass::Serialize cooking-target mask",
            )?;
        }

        debug_log!("udk_pcserver_script_cook: UClass::Serialize patch applied successfully");

        let (filter_offset, filter_count) =
            find_signature_offset(&FILTER_EDITOR_ONLY_SIG, FILTER_EDITOR_ONLY_MASK_OFFSET, 0);
        debug_log!("pcserver-script-cook editor-only filter mask matches: {filter_count}");

        let filter_offset =
            filter_offset.context("Failed to find the PLATFORM_FilterEditorOnly mask signature")?;
        let filter_address = range
            .start
            .saturating_add(filter_offset)
            .saturating_add(SIG_FILTER_MASK_LOW_BYTE_SKEW);

        debug_log!(
            "udk_pcserver_script_cook: clearing PLATFORM_WindowsServer from the editor-only filter mask at 0x{filter_address:X} (sig offset 0x{filter_offset:X}), so cooked script keeps the editor-only UProperty objects this binary's native class layout still has"
        );

        unsafe {
            write_byte(
                filter_address,
                COOKING_MASK_WITHOUT_WINDOWS_SERVER,
                "the editor-only filter mask",
            )?;
        }

        debug_log!("udk_pcserver_script_cook: filter mask patch applied successfully");

        let (non_native_offset, non_native_count) =
            find_signature_offset(&NON_NATIVE_SCRIPT_SIG, NON_NATIVE_SCRIPT_TEST_OFFSET, 0);
        debug_log!("pcserver-script-cook non-native script guard matches: {non_native_count}");

        let non_native_offset = non_native_offset
            .context("Failed to find the non-native script platform test signature")?;
        let non_native_address = range.start.saturating_add(non_native_offset);

        debug_log!(
            "udk_pcserver_script_cook: patching the non-native script platform test at 0x{non_native_address:X} (sig offset 0x{non_native_offset:X}) to CMP 2 / JA, so a PCServer cook actually writes the game's own script packages"
        );

        unsafe {
            write_byte(
                non_native_address.saturating_add(SIG_NON_NATIVE_IMMEDIATE_SKEW),
                PLATFORM_WINDOWS_SERVER,
                "the non-native script platform test immediate",
            )?;
            write_byte(
                non_native_address.saturating_add(SIG_NON_NATIVE_JUMP_OPCODE_SKEW),
                JA_REL8_OPCODE,
                "the non-native script platform test jump opcode",
            )?;
        }

        debug_log!("udk_pcserver_script_cook: non-native script patch applied successfully");

        let (sort_offset, sort_count) =
            find_signature_offset(&NON_NATIVE_SORT_SIG, NON_NATIVE_SORT_TEST_OFFSET, 0);
        debug_log!("pcserver-script-cook non-native sort guard matches: {sort_count}");

        let sort_offset = sort_offset
            .context("Failed to find the non-native script sort platform test signature")?;
        let sort_address = range.start.saturating_add(sort_offset);

        debug_log!(
            "udk_pcserver_script_cook: patching the non-native script sort test at 0x{sort_address:X} (sig offset 0x{sort_offset:X}) to CMP 2 / JA, so the game's script packages survive into the final cook list"
        );

        unsafe {
            write_byte(
                sort_address,
                PLATFORM_WINDOWS_SERVER,
                "the non-native script sort test immediate",
            )?;
            write_byte(
                sort_address.saturating_add(1),
                JA_REL8_OPCODE,
                "the non-native script sort test jump opcode",
            )?;
        }

        debug_log!("udk_pcserver_script_cook: non-native script sort patch applied successfully");

        let (save_offset, save_count) = find_signature_offset(
            &SAVE_COOKED_PC_BRANCH_SIG,
            SAVE_COOKED_PC_BRANCH_OFFSET,
            0,
        );
        debug_log!("pcserver-script-cook SaveCookedPackage branch matches: {save_count}");

        let save_offset = save_offset
            .context("Failed to find the SaveCookedPackage platform branch signature")?;
        let save_address = range.start.saturating_add(save_offset);

        debug_log!(
            "udk_pcserver_script_cook: patching SaveCookedPackage's platform branch at 0x{save_address:X} (sig offset 0x{save_offset:X}) to CMP 2 / JA, so a PCServer cook keeps non-texture objects, creates nested output directories and excludes shader caches"
        );

        unsafe {
            write_byte(
                save_address.saturating_add(SIG_SAVE_COOKED_IMMEDIATE_SKEW),
                PLATFORM_WINDOWS_SERVER,
                "the SaveCookedPackage platform branch immediate",
            )?;
            write_byte(
                save_address.saturating_add(SIG_SAVE_COOKED_JUMP_OPCODE_SKEW),
                JA_REL32_OPCODE,
                "the SaveCookedPackage platform branch jump opcode",
            )?;
        }

        debug_log!("udk_pcserver_script_cook: SaveCookedPackage patch applied successfully");
    }

    debug_log!("udk_pcserver_script_cook::init done");

    Ok(())
}
