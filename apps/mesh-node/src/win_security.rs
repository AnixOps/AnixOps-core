//! Windows access control for the device without the Agent
//! (`docs/deploy/mesh-device.md`): the state directory, created open to
//! SYSTEM and the administrators only, and the owner check a status pipe
//! client makes before it trusts the answer.

use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The state directory: full control for SYSTEM and the administrators,
/// nothing for anyone else, nothing inherited from above, and the same
/// entries on everything created inside.
pub const STATE_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// The status pipe: full control for SYSTEM and the administrators; the
/// local users may connect, read and write their one request
/// (`FILE_GENERIC_READ | FILE_WRITE_DATA`, 0x12008B) but not create pipe
/// instances of their own (`FILE_CREATE_PIPE_INSTANCE`, the append right,
/// is left out), change the access list or take ownership.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;BU)";

/// Owners a status pipe may have: SYSTEM and the administrators. The
/// caller's own account is accepted too: a pipe it made itself can only
/// mislead itself.
const TRUSTED_PIPE_OWNERS: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];

/// A security descriptor made from SDDL; freed when dropped.
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `text` is NUL-terminated; the system allocates the
        // descriptor, which `Drop` frees.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    /// Attributes pointing at this descriptor; valid while it lives.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by the system above, freed once.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Creates `dir` with [`STATE_DIR_SDDL`] in one step, so that it is never
/// open to others in between; the directories above are created as usual
/// when missing. An existing directory is left as it is: the state checks
/// (`check_state_dir`) then decide whether it may be used.
pub fn create_state_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let descriptor = SecurityDescriptor::from_sddl(STATE_DIR_SDDL)?;
    let attributes = descriptor.attributes();
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL-terminated; the attributes point at a live
    // descriptor.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error);
        }
    }
    Ok(())
}

/// A SID as its string form (`S-1-5-18`).
fn sid_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut text: *mut u16 = null_mut();
    // SAFETY: `sid` is a valid SID; `text` is allocated by the system and
    // freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return None;
    }
    // SAFETY: `text` is a NUL-terminated wide string.
    let string = unsafe {
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(text, len)).ok()
    };
    // SAFETY: allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(text.cast()) };
    string
}

/// The owner of a kernel object (a pipe handle) as a SID string.
pub fn handle_owner(handle: HANDLE) -> io::Result<String> {
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `handle` is open; the owner points into the descriptor the
    // system allocates, freed below after the owner is read.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let text = sid_string(owner);
    // SAFETY: allocated by GetSecurityInfo, freed once.
    unsafe { LocalFree(descriptor) };
    text.ok_or_else(|| io::Error::other("cannot read the owner"))
}

/// The account this process runs as, as a SID string.
pub fn current_account() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo handle of this process; `token` receives a handle
    // closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0u64; 64];
    let mut len = 0u32;
    // SAFETY: the buffer holds 512 bytes, aligned for TOKEN_USER.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * 8) as u32,
            &mut len,
        )
    };
    let error = io::Error::last_os_error();
    // SAFETY: opened above, closed once.
    unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
    if ok == 0 {
        return Err(error);
    }
    // SAFETY: on success the buffer starts with a TOKEN_USER.
    let sid = unsafe { (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid };
    sid_string(sid).ok_or_else(|| io::Error::other("cannot read this account"))
}

/// Whether a status pipe owned by `owner` may be trusted by a caller
/// running as `caller`.
pub fn trusted_pipe_owner(owner: &str, caller: &str) -> bool {
    TRUSTED_PIPE_OWNERS.contains(&owner) || owner == caller
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_system_the_administrators_or_oneself_own_a_trusted_pipe() {
        let me = "S-1-5-21-1-2-3-1001";
        assert!(trusted_pipe_owner("S-1-5-18", me));
        assert!(trusted_pipe_owner("S-1-5-32-544", me));
        assert!(trusted_pipe_owner(me, me));
        assert!(!trusted_pipe_owner("S-1-5-21-1-2-3-1002", me));
        assert!(!trusted_pipe_owner("S-1-5-32-545", me));
    }

    #[test]
    fn the_descriptors_parse() {
        SecurityDescriptor::from_sddl(STATE_DIR_SDDL).unwrap();
        SecurityDescriptor::from_sddl(PIPE_SDDL).unwrap();
    }

    #[test]
    fn a_state_dir_is_made_open_to_the_administrators_only() {
        let dir = std::env::temp_dir()
            .join(format!("anixops-mesh-acl-{}", std::process::id()))
            .join("device");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
        create_state_dir(&dir).unwrap();
        assert!(dir.is_dir());
        let (_, entries) = crate::host::windows::security(&dir).unwrap();
        let entries = entries.expect("an access list");
        assert!(!entries.is_empty());
        for entry in &entries {
            assert!(entry.known && entry.allow, "{entry:?}");
            assert!(
                ["S-1-5-18", "S-1-5-32-544"].contains(&entry.sid.as_str()),
                "{entry:?}"
            );
        }
        // A second call keeps the directory.
        create_state_dir(&dir).unwrap();
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn this_process_has_an_account() {
        assert!(current_account().unwrap().starts_with("S-1-"));
    }
}
