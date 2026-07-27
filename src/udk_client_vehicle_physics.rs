//! Hands the driving client authority over its own vehicle's rigid body.
//!
//! # What the stock engine does
//!
//! Every client already runs the complete vehicle simulation. `ASVehicle`
//! overrides `TickSimulated` to call `TickAuthoritative`, so a simulated proxy
//! performs the same PhysX step as the server. Two decisions inside
//! `ASVehicle::physRigidBody` are what make it look server-owned, and both are
//! gated on the same test:
//!
//! ```text
//! if(Role == ROLE_Authority) VehiclePackRBState();   // publish my pose
//! else                       VehicleUnpackRBState(); // be corrected to theirs
//! ...
//! if(Role == ROLE_Authority) SimObj->ProcessCarInput(this);      // my input
//! else { OutputGas = RangeByteToFloat(VState.ServerGas); ... }   // their input
//! ```
//!
//! The driving client therefore discards the throttle and steering it already
//! computed locally - `PlayerController`'s `PlayerDriving` state calls
//! `ProcessDrive` before `ServerDrive` - and waits a full round trip for
//! `VState.ServerGas` to come back, while `ApplyNewRBState` drags its body
//! toward a pose that is one round trip stale.
//!
//! # What this module changes
//!
//! `ROLE_AutonomousProxy` on a client means exactly "I am the driver of this
//! vehicle": `UActorChannel::ReplicateActor` rewrites `RemoteRole` to
//! `ROLE_SimulatedProxy` for every connection that does not own the actor, and
//! passengers are possessing their own seat pawn rather than the hull. So this
//! detours `physRigidBody` and, for an owned vehicle while armed, presents
//! `Role` as `ROLE_Authority` for the duration of the call. The engine then
//! packs its own state and runs its own input, and nothing else has to change.
//!
//! Raising `Role` rather than patching the two comparisons keeps the decision
//! per-vehicle and per-frame instead of process-wide, and leaves the code
//! section untouched. `physRigidBody` reads `Role` nowhere else, and it runs
//! only on the game thread, so the window is not observable.
//!
//! # Arming
//!
//! The server owns the decision. `Rx_Vehicle` replicates
//! `bClientPhysicsAuthority`, and the owning client echoes it down to this
//! module with `ConsoleCommand("RXVEHICLEAUTHORITY 1"/"0")`, which arrives here
//! through `ULocalPlayer::Exec`. A client carrying this DLL on a server whose
//! script never sets that flag is therefore unchanged, which is the case that
//! would otherwise desync. Only one vehicle is `ROLE_AutonomousProxy` on a
//! client at a time, so a single armed flag has exactly the right granularity.
//!
//! A dedicated server has no `ULocalPlayer`, never arms, and keeps its stock
//! behaviour - it stays the authority for parked vehicles, bots, and anyone the
//! feature is switched off for.
//!
//! RVAs were mapped in Ghidra from the symbol-bearing 2013
//! `UDK Source Build with symbols/UDK.exe` to `RenXSDK/UDK.exe`; both functions
//! are byte-identical between the two builds, and the prologues below are
//! validated before either detour is written.

#![cfg(target_arch = "x86_64")]

use anyhow::{bail, Context};
use retour::static_detour;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;

/// `AActor::Role`, confirmed at the same offset in the symbol-bearing build.
const ACTOR_ROLE_OFFSET: usize = 0xC2;
const ROLE_AUTONOMOUS_PROXY: u8 = 2;
const ROLE_AUTHORITY: u8 = 3;

/// Console command the vehicle script uses to arm and release this module.
const AUTHORITY_COMMAND: &[u8] = b"RXVEHICLEAUTHORITY";

/// A function whose prologue is verified before a detour is written over it.
struct HookTarget {
    name: &'static str,
    rva: usize,
    prologue: &'static [u8],
}

const PHYS_RIGID_BODY: HookTarget = HookTarget {
    name: "ASVehicle::physRigidBody",
    rva: 0x009C_F360,
    prologue: &[
        0x48, 0x8B, 0xC4, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48,
        0x8D, 0xA8, 0x68, 0xFE, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x60, 0x02, 0x00, 0x00,
    ],
};

const LOCAL_PLAYER_EXEC: HookTarget = HookTarget {
    name: "ULocalPlayer::Exec",
    rva: 0x0086_A4D0,
    prologue: &[
        0x48, 0x8B, 0xC4, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48,
        0x8D, 0xA8, 0x38, 0xFB, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x90, 0x05, 0x00, 0x00,
    ],
};

type PhysRigidBody = extern "C" fn(*mut c_void, f32);
type LocalPlayerExec = extern "C" fn(*mut c_void, *const u16, *mut c_void) -> i32;

static_detour! {
    static PhysRigidBodyHook: extern "C" fn(*mut c_void, f32);
}

static_detour! {
    static LocalPlayerExecHook: extern "C" fn(*mut c_void, *const u16, *mut c_void) -> i32;
}

/// TRUE while the server has granted the local driver authority over the
/// vehicle it currently occupies.
static AUTHORITY_ARMED: AtomicBool = AtomicBool::new(false);

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

/// Presents an owned vehicle to `physRigidBody` as though this were the server.
/// Returns TRUE when `Role` was raised and has to be put back.
unsafe fn elevate_owned_vehicle(vehicle: *mut c_void) -> bool {
    if vehicle.is_null() || !AUTHORITY_ARMED.load(Ordering::Relaxed) {
        return false;
    }
    let role = (vehicle as *mut u8).add(ACTOR_ROLE_OFFSET);
    // Simulated proxies are other people's vehicles and must keep being
    // corrected; a listen server is already ROLE_Authority and needs nothing.
    if role.read() != ROLE_AUTONOMOUS_PROXY {
        return false;
    }
    role.write(ROLE_AUTHORITY);
    true
}

extern "C" fn phys_rigid_body_hook(vehicle: *mut c_void, delta_time: f32) {
    let elevated = unsafe { elevate_owned_vehicle(vehicle) };
    PhysRigidBodyHook.call(vehicle, delta_time);
    if elevated {
        // Restore before anything else can observe it. Script still sees the
        // vehicle as an autonomous proxy, so its own Role tests are unchanged.
        unsafe {
            (vehicle as *mut u8)
                .add(ACTOR_ROLE_OFFSET)
                .write(ROLE_AUTONOMOUS_PROXY)
        };
    }
}

fn set_armed(enable: bool) {
    if AUTHORITY_ARMED.swap(enable, Ordering::Relaxed) != enable {
        debug_log!(
            "client vehicle physics authority {}",
            if enable { "armed" } else { "released" }
        );
    }
}

unsafe fn read_wide_command(command: *const u16) -> Option<Vec<u16>> {
    const MAX_COMMAND_UNITS: usize = 1024;
    if command.is_null() {
        return None;
    }

    let mut units = Vec::new();
    for index in 0..MAX_COMMAND_UNITS {
        let unit = command.add(index).read();
        if unit == 0 {
            return Some(units);
        }
        units.push(unit);
    }
    None
}

fn is_ascii_whitespace(unit: u16) -> bool {
    unit == b' ' as u16 || unit == b'\t' as u16 || unit == b'\r' as u16 || unit == b'\n' as u16
}

/// Parses `RXVEHICLEAUTHORITY <0|1>`, returning the requested state. Anything
/// else is not ours and falls through to the engine.
fn parse_authority_command(command: &[u16]) -> Option<bool> {
    let mut index = command.iter().position(|unit| !is_ascii_whitespace(*unit))?;

    for expected in AUTHORITY_COMMAND {
        let unit = *command.get(index)?;
        if unit > u8::MAX as u16 || !(unit as u8).eq_ignore_ascii_case(expected) {
            return None;
        }
        index += 1;
    }
    if !is_ascii_whitespace(*command.get(index)?) {
        return None;
    }
    while command
        .get(index)
        .is_some_and(|unit| is_ascii_whitespace(*unit))
    {
        index += 1;
    }

    let enable = match *command.get(index)? {
        unit if unit == b'0' as u16 => false,
        unit if unit == b'1' as u16 => true,
        _ => return None,
    };
    index += 1;
    if command[index..].iter().any(|unit| !is_ascii_whitespace(*unit)) {
        return None;
    }
    Some(enable)
}

extern "C" fn local_player_exec_hook(
    player: *mut c_void,
    command: *const u16,
    output_device: *mut c_void,
) -> i32 {
    if let Some(units) = unsafe { read_wide_command(command) } {
        if let Some(enable) = parse_authority_command(&units) {
            set_armed(enable);
            // Swallow it so the console does not report an unknown command.
            return 1;
        }
    }
    LocalPlayerExecHook.call(player, command, output_device)
}

pub fn init() -> anyhow::Result<()> {
    debug_log!("udk_client_vehicle_physics::init start");

    // Validate both prologues before installing the first detour, so an
    // unexpected binary leaves the process untouched.
    let phys_rigid_body_address = PHYS_RIGID_BODY.resolve()?;
    let local_player_exec_address = LOCAL_PLAYER_EXEC.resolve()?;

    unsafe {
        let phys_rigid_body: PhysRigidBody = std::mem::transmute(phys_rigid_body_address);
        PhysRigidBodyHook
            .initialize(phys_rigid_body, |vehicle, delta_time| {
                phys_rigid_body_hook(vehicle, delta_time)
            })
            .context("failed to set up ASVehicle::physRigidBody hook")?;

        let local_player_exec: LocalPlayerExec = std::mem::transmute(local_player_exec_address);
        LocalPlayerExecHook
            .initialize(local_player_exec, |player, command, output_device| {
                local_player_exec_hook(player, command, output_device)
            })
            .context("failed to set up ULocalPlayer::Exec hook")?;

        PhysRigidBodyHook
            .enable()
            .context("failed to enable ASVehicle::physRigidBody hook")?;
        LocalPlayerExecHook
            .enable()
            .context("failed to enable ULocalPlayer::Exec hook")?;
    }

    // Inert until Rx_Vehicle arms it, so a dedicated server and any client on a
    // server without the matching script keep stock behaviour.
    debug_log!("udk_client_vehicle_physics::init done");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_authority_command;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    #[test]
    fn parses_both_states() {
        assert_eq!(parse_authority_command(&wide("RXVEHICLEAUTHORITY 1")), Some(true));
        assert_eq!(parse_authority_command(&wide("RXVEHICLEAUTHORITY 0")), Some(false));
    }

    #[test]
    fn accepts_surrounding_whitespace_and_any_case() {
        assert_eq!(
            parse_authority_command(&wide("  rxVehicleAuthority\t1  ")),
            Some(true)
        );
    }

    #[test]
    fn rejects_other_commands_and_malformed_arguments() {
        assert_eq!(parse_authority_command(&wide("SETRES 1920x1080b")), None);
        // A command that merely starts the same must not be swallowed.
        assert_eq!(parse_authority_command(&wide("RXVEHICLEAUTHORITYEXTRA 1")), None);
        assert_eq!(parse_authority_command(&wide("RXVEHICLEAUTHORITY")), None);
        assert_eq!(parse_authority_command(&wide("RXVEHICLEAUTHORITY 2")), None);
        assert_eq!(parse_authority_command(&wide("RXVEHICLEAUTHORITY 1 0")), None);
    }
}
