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
//! | `context` | inspection plus camera-only navigation. No map/package mutation. **The default.** |
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
    ReadViewport = 10,
    ControlViewport = 11,
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
            Capability::ReadViewport => "read.viewport",
            Capability::ControlViewport => "control.viewport",
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
            Capability::ReadViewport => {
                "Read the active viewport camera, visible actors, and an on-demand screenshot."
            }
            Capability::ControlViewport => {
                "Move only the active viewport camera to frame an actor; does not edit the map."
            }
        }
    }

    /// Whether the GUI should mark this as needing a deliberate choice. Both of
    /// these can lose work that is not recoverable through undo - `Exec` because
    /// it covers saving and rebuilding as well as editing.
    pub const fn is_destructive(self) -> bool {
        matches!(self, Capability::WriteDelete | Capability::Exec)
    }

    /// Whether this is safe for map context. Camera navigation is included: it
    /// changes transient editor UI state, but never a map or package. Used to
    /// build the `context` preset, so a capability added later is excluded
    /// unless it explicitly opts in here.
    pub const fn is_read_only(self) -> bool {
        matches!(
            self,
            Capability::ReadStatus
                | Capability::ReadSelection
                | Capability::ReadProperties
                | Capability::ReadMap
                | Capability::ReadViewport
                // Camera navigation changes editor UI state, but not map or
                // package state. It is intentionally available in context mode.
                | Capability::ControlViewport
        )
    }
}

pub const ALL: [Capability; 12] = [
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
    Capability::ReadViewport,
    Capability::ControlViewport,
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Context = 0,
    Edit = 1,
    Full = 2,
    Custom = 3,
    /// Everything `Full` grants, and none of the asking.
    ///
    /// This is the one mode that cannot be arrived at by accident. It has the
    /// same capability mask as `Full`, so [`mode_for_mask`] never names it -
    /// editing bits until they happen to add up to "everything" gives `Full`.
    /// It is only ever entered by being asked for explicitly, because the thing
    /// it switches off is the mechanism that would otherwise ask.
    Dangerous = 4,
}

impl Mode {
    pub const fn id(self) -> &'static str {
        match self {
            Mode::Context => "context",
            Mode::Edit => "edit",
            Mode::Full => "full",
            Mode::Custom => "custom",
            Mode::Dangerous => "dangerous",
        }
    }

    pub const fn describe(self) -> &'static str {
        match self {
            Mode::Context => {
                "Map-safe context. The model can inspect and navigate the camera but cannot change maps or packages."
            }
            Mode::Edit => "Read, edit properties, and move actors. No deleting, no Exec.",
            Mode::Full => "Everything, including arbitrary editor commands.",
            Mode::Custom => "Per-capability, as set in the advanced menu.",
            Mode::Dangerous => {
                "(!) Everything, and no prompts, size limits or rate limits. Nothing will ask."
            }
        }
    }

    fn parse(value: &str) -> Option<Mode> {
        match value {
            "context" => Some(Mode::Context),
            "edit" => Some(Mode::Edit),
            "full" => Some(Mode::Full),
            "custom" => Some(Mode::Custom),
            "dangerous" => Some(Mode::Dangerous),
            _ => None,
        }
    }

    fn from_index(value: u8) -> Mode {
        match value {
            1 => Mode::Edit,
            2 => Mode::Full,
            3 => Mode::Custom,
            4 => Mode::Dangerous,
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
            Mode::Full | Mode::Dangerous => {
                for capability in ALL {
                    mask |= capability.bit();
                }
            }
        }
        Some(mask)
    }
}

/// `Full` is deliberately ahead of `Dangerous`, because [`mode_for_mask`] takes
/// the first match and the two share a mask. That ordering is what makes
/// `Dangerous` unreachable except by name.
pub const ALL_MODES: [Mode; 5] = [
    Mode::Context,
    Mode::Edit,
    Mode::Full,
    Mode::Dangerous,
    Mode::Custom,
];

/// Whether the operator has said, in advance, to stop asking.
///
/// Every prompt and every limit the bridge imposes exists because the caller
/// cannot be the one to decide. This is the operator deciding once, in advance,
/// that for this session it can be - which is a legitimate thing to want when
/// you are driving the editor yourself and the prompts are the slow part.
///
/// It does **not** switch off the audit log. A session with no prompts is the
/// one where a written record matters most, and nothing here is load-bearing for
/// performance.
pub fn confirmations_suppressed() -> bool {
    current_mode() == Mode::Dangerous
}

/// The warning shown before entering the mode - the last prompt there will be.
pub fn dangerous_warning() -> String {
    format!(
        "Turn on DANGEROUS mode?\n\nThis grants every capability and switches off everything that \
         would otherwise stop and ask you:\n\n    - no approval prompt before an editor command \
         runs (including MAP SAVE, ACTOR DELETE, BUILDLIGHTING)\n    - no approval prompt before \
         the connected program changes its own permissions\n    - no {} actor limit on a single \
         change\n    - no limit on how many changes a minute\n    - deleting no longer needs a \
         confirm flag\n\nA connected model will be able to modify and delete anything in this \
         editor, as fast as it can ask, without you seeing a single dialog. Undo is your only \
         safety net, and it does not cover everything an editor command can do.\n\nThis setting \
         persists across restarts until you change it back. Every action is still written to the \
         audit log.\n\nOnly do this if you are watching the editor and know what is connected.",
        super::guard::BLAST_RADIUS
    )
}

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
        if let Some(saved) = std::fs::read_to_string(policy_path())
            .ok()
            .as_deref()
            // Every Windows text editor writes a UTF-8 BOM, and the JSON parser
            // requires `{` as the first byte. Without this, hand-editing the
            // policy file silently reverts it to read-only on the next launch -
            // safe, but the user would never learn why their setting vanished.
            .map(|text| text.trim_start_matches('\u{feff}'))
        {
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

/// Where the policy is persisted, for the status view to show.
pub fn policy_file_path() -> std::path::PathBuf {
    policy_path()
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

/// The refusal a caller sees.
///
/// Written for a language model reading it mid-task, and it has to answer four
/// questions at once or the model will do the wrong thing:
///
/// 1. **This is not a failure.** A model that reads "denied" as a malfunction
///    retries it, then retries it a third way. Say plainly that the tool works
///    and a person switched it off.
/// 2. **Which switch.** The capability id is what the panel shows, so the model
///    can name the exact toggle when it asks.
/// 3. **It is reversible, by the user, right now.** Without this the model
///    treats the restriction as permanent and silently drops the request instead
///    of asking - which is the worst outcome, because the user never learns
///    their own setting is what blocked the work.
/// 4. **Do not route around it.** The workaround for any blocked tool is
///    `renx_exec`, so that door has to be closed explicitly.
pub fn deny_message(capability: Capability) -> String {
    format!(
        "Blocked by MCP policy - this is a setting, not an error. The user has turned '{}' off \
         for this editor bridge. ({}) The bridge is working normally and every other permitted \
         tool still functions.\n\nCurrent mode is '{}'.{}\n\nThe user can re-enable it at any \
         time, live, in the editor under Tools > RenX MCP > Control Panel (Ctrl+Alt+M), by \
         picking a mode or ticking '{}' under Advanced. It applies immediately - no restart and \
         no reconnect. If you need this capability, stop and ask the user to enable it, naming \
         '{}' so they know which toggle to flip. Do not attempt the same effect through another \
         tool or command.",
        capability.id(),
        capability.describe(),
        current_mode().id(),
        granting_modes_sentence(capability),
        capability.id(),
        capability.id(),
    )
}

/// Names the presets that would grant `capability`, so the user can be asked for
/// the smallest change that unblocks the work rather than "give me full access".
///
/// `Dangerous` is excluded on purpose. It grants everything, so it would appear
/// in every one of these sentences, and a refusal that ends "...or ask them for
/// dangerous mode" teaches a blocked model to request the removal of all the
/// safeguards as a routine way past an obstacle. That mode is the operator's
/// choice to volunteer, never something a refusal suggests.
fn granting_modes_sentence(capability: Capability) -> String {
    let granting: Vec<&str> = ALL_MODES
        .iter()
        .filter(|mode| **mode != Mode::Dangerous)
        .filter(|mode| matches!(mode.mask(), Some(mask) if mask & capability.bit() != 0))
        .map(|mode| mode.id())
        .collect();
    match granting.len() {
        0 => String::new(),
        1 => format!(" This capability is granted by '{}' mode.", granting[0]),
        _ => format!(
            " This capability is granted by these modes: {}.",
            granting.join(", ")
        ),
    }
}

/// The refusal when a tool needs any one of several capabilities and has none of
/// them - `renx_actor_action`, whose capability depends on the `action`
/// argument. Naming only the first would send the user to the wrong toggle.
pub fn deny_message_any(capabilities: &[Capability]) -> String {
    let ids: Vec<&str> = capabilities.iter().map(|item| item.id()).collect();
    format!(
        "Blocked by MCP policy - this is a setting, not an error. This tool needs one of {}, and \
         the user has turned all of them off for this editor bridge. The bridge is working \
         normally and every other permitted tool still functions.\n\nCurrent mode is '{}'.\n\nThe \
         user can re-enable any of them at any time, live, in the editor under Tools > RenX MCP > \
         Control Panel (Ctrl+Alt+M), by picking a mode or ticking the capability under Advanced. \
         It applies immediately - no restart and no reconnect. If you need this, stop and ask the \
         user, naming the specific capability you need so they know which toggle to flip. Do not \
         attempt the same effect through another tool or command.",
        ids.join(", "),
        current_mode().id(),
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

/// A requested policy change, worked out but not yet applied.
///
/// Separating deciding from doing is what lets an untrusted request be
/// described to a human *before* it takes effect - see [`Change::summary`].
pub struct Change {
    mode: Mode,
    mask: u32,
    grants: Vec<Capability>,
    revokes: Vec<Capability>,
}

impl Change {
    /// Whether this hands out anything the bridge does not already have.
    ///
    /// This is the whole test for whether a human has to be asked. A request
    /// that only gives permissions up cannot be an escalation no matter who
    /// sent it, so it is applied without interrupting anyone; a request that
    /// takes on even one new capability is exactly the thing the policy exists
    /// to stop the caller doing for itself.
    pub fn grants_anything(&self) -> bool {
        !self.grants.is_empty() || self.enables_dangerous()
    }

    /// Switching the prompts off is itself a widening, even though it moves no
    /// capability bit. Without this, `full` -> `dangerous` would grant nothing
    /// by the mask test and so would apply unasked - which is precisely the
    /// change nobody should be able to make on the operator's behalf.
    pub fn enables_dangerous(&self) -> bool {
        self.mode == Mode::Dangerous && current_mode() != Mode::Dangerous
    }

    /// The prompt text. Written so someone who did not expect the dialog can
    /// tell what it is asking for and say no.
    pub fn summary(&self) -> String {
        // Asking for DANGEROUS is not a permission request like the others: it
        // asks for this dialog never to appear again. Say that first, in place
        // of the ordinary wording, or the last prompt looks like all the rest.
        if self.enables_dangerous() {
            return format!(
                "A program connected to this editor's MCP bridge is asking to turn on DANGEROUS \
                 mode.\n\nThis is the last time you will be asked about anything.\n\n{}",
                dangerous_warning()
            );
        }
        let mut text = String::from(
            "A program connected to this editor's MCP bridge is asking to change what it is \
             allowed to do.\n\nOnly allow this if you were expecting it.\n\n",
        );
        text.push_str(&format!(
            "Requested mode:  {}\nCurrent mode:    {}\n",
            self.mode.id(),
            current_mode().id()
        ));
        if !self.grants.is_empty() {
            text.push_str("\nThis would GRANT:\n");
            for capability in &self.grants {
                text.push_str(&format!(
                    "    {}{}\n        {}\n",
                    capability.id(),
                    if capability.is_destructive() {
                        "   (!) can destroy work"
                    } else {
                        ""
                    },
                    capability.describe()
                ));
            }
        }
        if !self.revokes.is_empty() {
            text.push_str("\nThis would remove:\n");
            for capability in &self.revokes {
                text.push_str(&format!("    {}\n", capability.id()));
            }
        }
        text.push_str("\nChoosing No leaves the current policy exactly as it is.");
        text
    }
}

/// Works out what a control request would do, without doing it.
pub fn plan(request: &str) -> Result<Change, String> {
    init();
    plan_from(request, MASK.load(Ordering::Acquire))
}

/// Split out so it can be exercised against a chosen starting mask rather than
/// the process-wide one, which every other test would then race against.
fn plan_from(request: &str, current: u32) -> Result<Change, String> {
    let requested_mode = match super::json_field_string(request, "mode") {
        Some(value) => {
            Some(Mode::parse(&value).ok_or_else(|| format!("unknown mode '{value}'"))?)
        }
        None => None,
    };
    let has_capabilities = super::json_field_raw(request, "capabilities").is_some();
    if requested_mode.is_none() && !has_capabilities {
        return Err("request must set 'mode', 'capabilities', or both".to_string());
    }

    let base = match requested_mode {
        Some(mode) => mode.mask().unwrap_or(current),
        None => current,
    };
    let mask = mask_from_json(request, base);

    // A preset whose bits were then edited is no longer that preset. Naming the
    // mask is the same rule the panel uses, so both surfaces agree on what to
    // call the result.
    // `Custom` and `Dangerous` are both named rather than derived: the first
    // because its mask is whatever it is, the second because it shares `Full`'s
    // mask and must never be inferred from one.
    let mode = match requested_mode {
        Some(Mode::Custom) => Mode::Custom,
        Some(Mode::Dangerous) if mask == Mode::Dangerous.mask().unwrap_or_default() => {
            Mode::Dangerous
        }
        _ => mode_for_mask(mask),
    };

    Ok(Change {
        mode,
        mask,
        grants: ALL
            .into_iter()
            .filter(|capability| {
                mask & capability.bit() != 0 && current & capability.bit() == 0
            })
            .collect(),
        revokes: ALL
            .into_iter()
            .filter(|capability| {
                mask & capability.bit() == 0 && current & capability.bit() != 0
            })
            .collect(),
    })
}

/// Puts a planned change into effect. Reaching here means it is authorised -
/// either it granted nothing, or a human said yes.
pub fn commit(change: &Change) -> String {
    let Ok(_guard) = WRITE_LOCK.lock() else {
        return policy_json();
    };
    store(change.mode, change.mask);
    save(change.mode, change.mask);
    policy_json()
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

    /// The safety property that makes the mode safe to offer at all: no amount
    /// of bit-editing can land on it, so it can only be entered deliberately.
    #[test]
    fn dangerous_is_never_inferred_from_a_mask() {
        let everything = Mode::Full.mask().unwrap();
        assert_eq!(Mode::Dangerous.mask(), Some(everything));
        assert!(
            mode_for_mask(everything) == Mode::Full,
            "the full mask must name itself Full, never Dangerous"
        );
        for capability in ALL {
            let one_off = everything & !capability.bit();
            assert!(mode_for_mask(one_off) != Mode::Dangerous);
        }
    }

    /// Turning the prompts off moves no capability bit, so the plain grant test
    /// would let it through unasked - the one change that must never apply on
    /// the operator's behalf.
    #[test]
    fn entering_dangerous_counts_as_widening_even_from_full() {
        let everything = Mode::Full.mask().unwrap();
        let change = plan_from(r#"{"mode":"dangerous"}"#, everything).unwrap();
        assert!(change.grants.is_empty(), "no capability bit moves");
        assert!(change.enables_dangerous());
        assert!(change.grants_anything(), "and yet it must still ask");
        assert!(change.summary().contains("DANGEROUS"), "{}", change.summary());
        assert!(
            change.summary().contains("last time you will be asked"),
            "{}",
            change.summary()
        );
    }

    #[test]
    fn dangerous_grants_every_capability() {
        let change = plan_from(r#"{"mode":"dangerous"}"#, Mode::Context.mask().unwrap()).unwrap();
        assert_eq!(change.mode.id(), "dangerous");
        assert_eq!(change.mask, Mode::Full.mask().unwrap());
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

    /// The refusal is the only thing a model sees when a capability is off, so
    /// each of the four things it has to convey is asserted rather than assumed.
    #[test]
    fn deny_message_tells_the_model_a_person_switched_it_off_and_can_switch_it_back() {
        for capability in ALL {
            let message = deny_message(capability);
            assert!(
                message.contains(capability.id()),
                "must name the toggle: {message}"
            );
            assert!(
                message.contains("setting, not an error"),
                "must not read as a malfunction: {message}"
            );
            assert!(
                message.contains("The user can re-enable it"),
                "must say it is reversible by the user: {message}"
            );
            assert!(
                message.contains("Tools > RenX MCP"),
                "must say where in the editor to find it: {message}"
            );
            assert!(
                message.contains("ask the user"),
                "must direct the model to ask rather than give up: {message}"
            );
            assert!(
                message.contains("another tool"),
                "must close the renx_exec workaround: {message}"
            );
        }
    }

    #[test]
    fn deny_message_names_the_modes_that_would_grant_it() {
        assert!(deny_message(Capability::Exec).contains("'full' mode"));
        // Never route a blocked model towards switching the safeguards off.
        for capability in ALL {
            assert!(
                !deny_message(capability).contains("dangerous"),
                "{} suggests dangerous mode",
                capability.id()
            );
        }
        // Granted by both `edit` and `full`, so the user can be asked for the
        // smaller of the two rather than for everything.
        let transform = deny_message(Capability::WriteTransform);
        assert!(transform.contains("edit"), "{transform}");
        assert!(transform.contains("full"), "{transform}");
    }

    #[test]
    fn deny_message_any_names_every_candidate_capability() {
        let message = deny_message_any(&[
            Capability::WriteTransform,
            Capability::WriteDuplicate,
            Capability::WriteDelete,
        ]);
        assert!(message.contains("write.transform"), "{message}");
        assert!(message.contains("write.duplicate"), "{message}");
        assert!(message.contains("write.delete"), "{message}");
        assert!(message.contains("setting, not an error"), "{message}");
    }

    /// The whole point of the confirmation gate: widening needs a human, and
    /// narrowing must not, or a model could not drop a permission it no longer
    /// wants without interrupting someone.
    #[test]
    fn only_widening_a_policy_needs_confirmation() {
        let context = Mode::Context.mask().unwrap();
        let edit = Mode::Edit.mask().unwrap();
        let full = Mode::Full.mask().unwrap();

        let widen = plan_from(r#"{"mode":"full"}"#, context).unwrap();
        assert!(widen.grants_anything(), "context -> full must ask");

        let same = plan_from(r#"{"mode":"context"}"#, context).unwrap();
        assert!(!same.grants_anything(), "no change must not ask");
        assert!(same.revokes.is_empty(), "and takes nothing away either");

        let narrow = plan_from(r#"{"mode":"context"}"#, full).unwrap();
        assert!(!narrow.grants_anything(), "full -> context must not ask");
        assert!(!narrow.revokes.is_empty());

        // Mixed: one bit up and one down still counts as widening, or the gate
        // could be walked past by pairing every grant with a throwaway revoke.
        let mixed = plan_from(
            r#"{"capabilities":{"exec.command":true,"write.transform":false}}"#,
            edit,
        )
        .unwrap();
        assert!(mixed.grants_anything(), "any new bit must ask");
        assert!(!mixed.revokes.is_empty(), "and it still records the revoke");
    }

    #[test]
    fn a_change_summary_names_what_it_would_grant() {
        let summary = plan_from(r#"{"mode":"full"}"#, Mode::Context.mask().unwrap())
            .unwrap()
            .summary();
        assert!(summary.contains("exec.command"), "{summary}");
        assert!(summary.contains("write.delete"), "{summary}");
        assert!(summary.contains("GRANT"), "{summary}");
        assert!(summary.contains("can destroy work"), "{summary}");
        assert!(summary.contains("No leaves the current policy"), "{summary}");
    }

    /// A plan that applied itself would defeat the point of asking first.
    #[test]
    fn planning_does_not_change_anything_on_its_own() {
        let before = MASK.load(Ordering::Acquire);
        let _ = plan_from(r#"{"mode":"full"}"#, Mode::Context.mask().unwrap()).unwrap();
        assert_eq!(before, MASK.load(Ordering::Acquire));
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
