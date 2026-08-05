//! What the MCP bridge is allowed to do to the editor, and who gets to decide.
//!
//! # Why a policy layer exists
//!
//! The bridge hands a language model a live UE3 editor. `renx_exec` alone is
//! arbitrary `Exec` on the editor thread - it can save packages, delete actors,
//! rebuild lighting, or run any console command the editor understands - and the
//! only guard the tools shipped with was `delete requires confirm=true`, which a
//! model can satisfy by passing `confirm: true`.
//!
//! A confirmation flag is not a permission system. It asks the caller to agree
//! with itself. This module puts the decision somewhere the caller cannot reach:
//! a capability mask owned by the process and set by a human through a GUI.
//!
//! # Modes are presets over one capability mask
//!
//! There is exactly one enforcement primitive - a bit per [`Capability`] - and
//! modes are named bit patterns over it. That keeps "context mode makes no
//! edits" and "advanced menu turns off just delete" the same mechanism rather
//! than two systems that can disagree.
//!
//! | mode | what it grants |
//! |---|---|
//! | `context` | every read. No mutation of any kind. **The default.** |
//! | `edit` | reads, property writes, transforms, duplicate. No delete, no exec. |
//! | `full` | everything, including `renx_exec`. |
//! | `custom` | whatever the advanced menu set, bit by bit. |
//!
//! `context` is the default on purpose. A bridge that starts permissive and
//! waits to be locked down is wrong the first time it is used before anyone has
//! opened the GUI - which is exactly when nobody is watching.
//!
//! # Where it is enforced
//!
//! Three places, deliberately redundant, and only the last one is load bearing:
//!
//! 1. `tools/list` hides tools the mode forbids, so discovery matches reality
//!    and the model is not invited to try something that will fail.
//! 2. `tools/call` rejects a forbidden tool before parsing its arguments.
//! 3. [`super::submit_editor_operation`] classifies the decoded
//!    [`super::EditorOperation`] and refuses there.
//!
//! Point 3 is the security boundary: it sits below the JSON layer, on the one
//! path every tool must take to reach the editor thread, so a tool added later
//! that forgets to check is still contained. Points 1 and 2 exist so the failure
//! is legible instead of mysterious.

use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Mutex;

/// One switchable permission. Values are a bit index, so there is room for 32.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    ReadStatus = 0,
    ReadSelection = 1,
    ReadProperties = 2,
    ReadMap = 3,
    WriteActorProperty = 4,
    WriteObjectProperty = 5,
    WriteTransform = 6,
    WriteDuplicate = 7,
    WriteDelete = 8,
    Exec = 9,
}

impl Capability {
    const fn bit(self) -> u32 {
        1u32 << (self as u32)
    }

    /// Stable identifier. This is what the GUI stores and posts back, so it is
    /// part of the interface and must not be renamed casually.
    pub const fn id(self) -> &'static str {
        match self {
            Capability::ReadStatus => "read.status",
            Capability::ReadSelection => "read.selection",
            Capability::ReadProperties => "read.properties",
            Capability::ReadMap => "read.map",
            Capability::WriteActorProperty => "write.actor_property",
            Capability::WriteObjectProperty => "write.object_property",
            Capability::WriteTransform => "write.transform",
            Capability::WriteDuplicate => "write.duplicate",
            Capability::WriteDelete => "write.delete",
            Capability::Exec => "exec.command",
        }
    }

    /// Shown next to the toggle in the advanced menu.
    pub const fn describe(self) -> &'static str {
        match self {
            Capability::ReadStatus => "Report bridge and editor readiness.",
            Capability::ReadSelection => "Read the current selection and each actor's transform.",
            Capability::ReadProperties => "List and export reflected properties.",
            Capability::ReadMap => "Report the loaded map and its levels.",
            Capability::WriteActorProperty => "Set a reflected property on a selected actor.",
            Capability::WriteObjectProperty => "Set a reflected property on any object path.",
            Capability::WriteTransform => "Reset, snap, and grid-align selected actors.",
            Capability::WriteDuplicate => "Duplicate selected actors.",
            Capability::WriteDelete => "Delete selected actors.",
            Capability::Exec => "Run arbitrary UE3 editor Exec commands.",
        }
    }

    /// Whether the GUI should mark this as needing a deliberate choice. Both of
    /// these can lose work that is not recoverable through undo - `Exec` because
    /// it covers saving and rebuilding as well as editing.
    pub const fn is_destructive(self) -> bool {
        matches!(self, Capability::WriteDelete | Capability::Exec)
    }

    /// Whether this only reads. Used to build the `context` preset, so a
    /// capability added later is excluded from read-only mode unless it says
    /// otherwise here.
    pub const fn is_read_only(self) -> bool {
        matches!(
            self,
            Capability::ReadStatus
                | Capability::ReadSelection
                | Capability::ReadProperties
                | Capability::ReadMap
        )
    }
}

pub const ALL: [Capability; 10] = [
    Capability::ReadStatus,
    Capability::ReadSelection,
    Capability::ReadProperties,
    Capability::ReadMap,
    Capability::WriteActorProperty,
    Capability::WriteObjectProperty,
    Capability::WriteTransform,
    Capability::WriteDuplicate,
    Capability::WriteDelete,
    Capability::Exec,
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Context = 0,
    Edit = 1,
    Full = 2,
    Custom = 3,
}

impl Mode {
    pub const fn id(self) -> &'static str {
        match self {
            Mode::Context => "context",
            Mode::Edit => "edit",
            Mode::Full => "full",
            Mode::Custom => "custom",
        }
    }

    pub const fn describe(self) -> &'static str {
        match self {
            Mode::Context => "Read-only. The model can inspect the editor but cannot change it.",
            Mode::Edit => "Read, edit properties, and move actors. No deleting, no Exec.",
            Mode::Full => "Everything, including arbitrary editor commands.",
            Mode::Custom => "Per-capability, as set in the advanced menu.",
        }
    }

    fn parse(value: &str) -> Option<Mode> {
        match value {
            "context" => Some(Mode::Context),
            "edit" => Some(Mode::Edit),
            "full" => Some(Mode::Full),
            "custom" => Some(Mode::Custom),
            _ => None,
        }
    }

    fn from_index(value: u8) -> Mode {
        match value {
            1 => Mode::Edit,
            2 => Mode::Full,
            3 => Mode::Custom,
            _ => Mode::Context,
        }
    }

    /// The mask a preset stands for. `Custom` has no fixed mask - it keeps
    /// whatever the advanced menu last set - so it is not answerable here.
    fn mask(self) -> Option<u32> {
        let mut mask = 0;
        match self {
            Mode::Custom => return None,
            Mode::Context => {
                for capability in ALL {
                    if capability.is_read_only() {
                        mask |= capability.bit();
                    }
                }
            }
            Mode::Edit => {
                for capability in ALL {
                    if capability.is_read_only() || !capability.is_destructive() {
                        mask |= capability.bit();
                    }
                }
            }
            Mode::Full => {
                for capability in ALL {
                    mask |= capability.bit();
                }
            }
        }
        Some(mask)
    }
}

pub const ALL_MODES: [Mode; 4] = [Mode::Context, Mode::Edit, Mode::Full, Mode::Custom];

/// Read on every tool call, so it is an atomic rather than living behind the
/// mutex that serialises writes.
static MASK: AtomicU32 = AtomicU32::new(0);
static MODE: AtomicU8 = AtomicU8::new(Mode::Context as u8);
/// Serialises policy changes against each other and against the file write, so
/// two GUIs cannot interleave a mode switch with a per-capability toggle.
static WRITE_LOCK: Mutex<()> = Mutex::new(());
static LOADED: std::sync::Once = std::sync::Once::new();

/// Applies the startup policy: `RENX_MCP_MODE` if set, otherwise the saved
/// policy file, otherwise read-only.
///
/// Failing to read either leaves `context`, because the fallback for "I do not
/// know what I am allowed to do" is to do nothing.
pub fn init() {
    LOADED.call_once(|| {
        if let Some(mode) = std::env::var("RENX_MCP_MODE")
            .ok()
            .and_then(|value| Mode::parse(value.trim().to_ascii_lowercase().as_str()))
        {
            store(mode, mode.mask().unwrap_or(Mode::Context.mask().unwrap()));
            return;
        }
        if let Some(saved) = std::fs::read_to_string(policy_path()).ok().as_deref() {
            if let Some(mode) =
                super::json_field_string(saved, "mode").and_then(|value| Mode::parse(&value))
            {
                let mask = match mode.mask() {
                    Some(mask) => mask,
                    None => mask_from_json(saved, 0),
                };
                store(mode, mask);
                return;
            }
        }
        store(Mode::Context, Mode::Context.mask().unwrap());
    });
}

fn store(mode: Mode, mask: u32) {
    MASK.store(mask, Ordering::Release);
    MODE.store(mode as u8, Ordering::Release);
}

/// Beside `UDK.exe`, like every other file this DLL writes.
fn policy_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("RenXMcpPolicy.json")))
        .unwrap_or_else(|| std::path::PathBuf::from("RenXMcpPolicy.json"))
}

/// Reads `capabilities` out of a control request or saved file. Absent keys keep
/// `base`, so a GUI can post a single toggle without restating the whole set.
fn mask_from_json(object: &str, base: u32) -> u32 {
    let Some(capabilities) = super::json_field_raw(object, "capabilities") else {
        return base;
    };
    let mut mask = base;
    for capability in ALL {
        match super::json_field_bool(capabilities, capability.id()) {
            Some(true) => mask |= capability.bit(),
            Some(false) => mask &= !capability.bit(),
            None => {}
        }
    }
    mask
}

pub fn allows(capability: Capability) -> bool {
    init();
    MASK.load(Ordering::Acquire) & capability.bit() != 0
}

pub fn current_mode() -> Mode {
    init();
    Mode::from_index(MODE.load(Ordering::Acquire))
}

/// The refusal a caller sees. It names the capability and the switch that would
/// grant it, because a model that is told only "denied" will retry the same call
/// or invent a workaround - and the workaround for a blocked tool is `renx_exec`.
pub fn deny_message(capability: Capability) -> String {
    format!(
        "blocked by editor policy: '{}' is disabled in {} mode. {} This is set by the operator in \
         the RenX MCP control panel and cannot be changed from here; ask them to enable it. Do not \
         attempt the same effect through another tool.",
        capability.id(),
        current_mode().id(),
        capability.describe()
    )
}

/// Everything a GUI needs to render both the mode picker and the advanced menu,
/// including the descriptions, so the panel does not carry its own copy of this
/// list and drift from it.
pub fn policy_json() -> String {
    init();
    let mask = MASK.load(Ordering::Acquire);
    let mode = current_mode();

    let mut modes = String::new();
    for (index, candidate) in ALL_MODES.iter().enumerate() {
        if index > 0 {
            modes.push(',');
        }
        modes.push_str(&format!(
            "{{\"id\":\"{}\",\"description\":\"{}\",\"selected\":{}}}",
            candidate.id(),
            super::json_escape(candidate.describe()),
            *candidate == mode
        ));
    }

    let mut capabilities = String::new();
    for (index, capability) in ALL.iter().enumerate() {
        if index > 0 {
            capabilities.push(',');
        }
        capabilities.push_str(&format!(
            "{{\"id\":\"{}\",\"description\":\"{}\",\"enabled\":{},\"destructive\":{},\"readOnly\":{}}}",
            capability.id(),
            super::json_escape(capability.describe()),
            mask & capability.bit() != 0,
            capability.is_destructive(),
            capability.is_read_only()
        ));
    }

    format!(
        "{{\"mode\":\"{}\",\"modes\":[{modes}],\"capabilities\":[{capabilities}],\"persistedTo\":\"{}\"}}",
        mode.id(),
        super::json_escape(&policy_path().to_string_lossy())
    )
}

/// Selects a preset. Used by the in-editor panel, which has typed controls and
/// no reason to round-trip through JSON to reach the same place.
pub fn apply_mode(mode: Mode) {
    let Ok(_guard) = WRITE_LOCK.lock() else {
        return;
    };
    init();
    let mask = mode.mask().unwrap_or_else(|| MASK.load(Ordering::Acquire));
    store(mode, mask);
    save(mode, mask);
}

/// Toggles one capability, moving the policy to `custom` if the result no longer
/// matches the preset it came from.
pub fn apply_capability(capability: Capability, enabled: bool) {
    let Ok(_guard) = WRITE_LOCK.lock() else {
        return;
    };
    init();
    let mask = if enabled {
        MASK.load(Ordering::Acquire) | capability.bit()
    } else {
        MASK.load(Ordering::Acquire) & !capability.bit()
    };
    store(mode_for_mask(mask), mask);
    save(mode_for_mask(mask), mask);
}

/// Names a mask: a preset if it matches one exactly, `custom` otherwise. This is
/// what keeps the mode label in the GUI honest after an advanced-menu edit.
fn mode_for_mask(mask: u32) -> Mode {
    for candidate in ALL_MODES {
        if candidate.mask() == Some(mask) {
            return candidate;
        }
    }
    Mode::Custom
}

/// Applies a control request and returns the new policy.
///
/// `{"mode":"context"}` selects a preset. `{"capabilities":{"exec.command":false}}`
/// toggles individual bits and moves the policy to `custom`, because a preset
/// that no longer matches its own definition would be a lie in the GUI.
pub fn apply(request: &str) -> Result<String, String> {
    init();
    let _guard = WRITE_LOCK.lock().map_err(|_| "policy lock poisoned")?;

    let requested_mode = match super::json_field_string(request, "mode") {
        Some(value) => Some(
            Mode::parse(&value).ok_or_else(|| format!("unknown mode '{value}'"))?,
        ),
        None => None,
    };
    let has_capabilities = super::json_field_raw(request, "capabilities").is_some();
    if requested_mode.is_none() && !has_capabilities {
        return Err("request must set 'mode', 'capabilities', or both".to_string());
    }

    let base = match requested_mode {
        Some(mode) => mode.mask().unwrap_or_else(|| MASK.load(Ordering::Acquire)),
        None => MASK.load(Ordering::Acquire),
    };
    let mask = mask_from_json(request, base);

    // A preset whose bits were then edited is no longer that preset. Naming the
    // mask is the same rule the panel uses, so both surfaces agree on what to
    // call the result.
    let mode = match requested_mode {
        Some(Mode::Custom) => Mode::Custom,
        _ => mode_for_mask(mask),
    };

    store(mode, mask);
    save(mode, mask);
    Ok(policy_json())
}

/// Best effort: a policy that cannot be persisted is still enforced for this
/// session, and saying so is more useful than refusing the change.
fn save(mode: Mode, mask: u32) {
    let mut capabilities = String::new();
    for (index, capability) in ALL.iter().enumerate() {
        if index > 0 {
            capabilities.push(',');
        }
        capabilities.push_str(&format!(
            "\"{}\":{}",
            capability.id(),
            mask & capability.bit() != 0
        ));
    }
    let body = format!(
        "{{\"mode\":\"{}\",\"capabilities\":{{{capabilities}}}}}",
        mode.id()
    );
    if let Err(error) = std::fs::write(policy_path(), body) {
        crate::patch_utils::debug_log!("RenX MCP could not persist policy: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_mode_grants_no_writes() {
        let mask = Mode::Context.mask().unwrap();
        for capability in ALL {
            let granted = mask & capability.bit() != 0;
            assert_eq!(
                granted,
                capability.is_read_only(),
                "{} wrongly {} in context mode",
                capability.id(),
                if granted { "granted" } else { "denied" }
            );
        }
    }

    #[test]
    fn edit_mode_withholds_delete_and_exec() {
        let mask = Mode::Edit.mask().unwrap();
        assert_eq!(mask & Capability::WriteDelete.bit(), 0);
        assert_eq!(mask & Capability::Exec.bit(), 0);
        assert_ne!(mask & Capability::WriteActorProperty.bit(), 0);
        assert_ne!(mask & Capability::WriteTransform.bit(), 0);
    }

    #[test]
    fn full_mode_grants_everything() {
        let mask = Mode::Full.mask().unwrap();
        for capability in ALL {
            assert_ne!(mask & capability.bit(), 0, "{}", capability.id());
        }
    }

    #[test]
    fn capability_ids_are_unique() {
        for (index, left) in ALL.iter().enumerate() {
            for right in ALL.iter().skip(index + 1) {
                assert_ne!(left.id(), right.id());
                assert_ne!(left.bit(), right.bit());
            }
        }
    }

    #[test]
    fn toggling_a_bit_off_a_preset_yields_custom() {
        // Starting from `full`, turning exec off is no longer `full`.
        let base = Mode::Full.mask().unwrap();
        let toggled = base & !Capability::Exec.bit();
        assert_ne!(Mode::Full.mask(), Some(toggled));
        assert_ne!(Mode::Edit.mask(), Some(toggled));
    }
}
