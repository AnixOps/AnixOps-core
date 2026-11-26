//! Files the elevated GUI and the service keep under `%ProgramData%\AnixOps`.
//!
//! `%ProgramData%` lets every user create folders and files in it, and a
//! folder or file keeps the owner and access list it was created with. A
//! standard user could therefore create the product folder before the
//! product does, or leave a file at the temporary name an elevated writer
//! later renames over a managed file, and then own what the elevated
//! process trusts (engine configuration, nodes, plug-in scripts, the logon
//! task definition). The functions here close that:
//!
//! - every folder from `%ProgramData%\AnixOps` down to the one written is
//!   created with an explicit, protected access list (SYSTEM and
//!   Administrators full control, Users read) owned by Administrators. An
//!   existing folder that is a reparse point (junction or symbolic link) is
//!   refused; one with another owner or with an inherited access list, as
//!   earlier versions left them, is taken over by Administrators and reset,
//!   and so are the folders below it;
//! - a file is replaced by writing a temporary file with a random name,
//!   created exclusively (`CREATE_NEW`, so an existing file or link at that
//!   name is never opened) with the same protected access list, and moving
//!   it over the target;
//! - a managed file is read only when it is not a reparse point and SYSTEM,
//!   Administrators or the account running this process owns it.
//!
//! Paths outside the managed root, and every path on other platforms, are
//! written through the same random exclusive temporary file without the
//! access-list handling.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

/// The product folder under `%ProgramData%` that holds every managed file.
pub const WINDOWS_MANAGED_ROOT_DIRECTORY: &str = "AnixOps";

/// `%ProgramData%` (or `C:\ProgramData` when the variable is missing).
pub fn program_data_directory() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

/// `%ProgramData%\AnixOps`: the root every protected folder hangs from.
pub fn windows_managed_root_directory() -> PathBuf {
    program_data_directory().join(WINDOWS_MANAGED_ROOT_DIRECTORY)
}

/// Whether `path` lies under [`windows_managed_root_directory`] (or is it),
/// without `.` or `..` components that could step out of it.
pub fn is_within_managed_root(path: &Path) -> bool {
    !path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        && path.starts_with(windows_managed_root_directory())
}

/// Creates `directory` and every folder between it and the managed root
/// with the protected access list, or verifies and repairs the ones that
/// exist. A directory outside the managed root is only created.
pub fn ensure_managed_directory(directory: &Path) -> io::Result<()> {
    if !is_within_managed_root(directory) {
        return fs::create_dir_all(directory);
    }
    let root = windows_managed_root_directory();
    let relative = directory
        .strip_prefix(&root)
        .map_err(|_| invalid_input("managed directory is outside the managed root"))?;
    native::ensure_protected_directory(&root)?;
    let mut current = root;
    for component in relative.components() {
        match component {
            Component::Normal(name) => current.push(name),
            _ => return Err(invalid_input("managed directory has an invalid component")),
        }
        native::ensure_protected_directory(&current)?;
    }
    Ok(())
}

/// Replaces `path` with `bytes`: a new temporary file with a random name is
/// created exclusively next to it (with the protected access list under the
/// managed root), written, flushed and moved over `path`.
pub fn write_managed_file_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| invalid_input("managed path has no parent"))?;
    let stem = path
        .file_name()
        .ok_or_else(|| invalid_input("managed path has no file name"))?
        .to_string_lossy()
        .into_owned();
    let managed = is_within_managed_root(path);
    if managed {
        ensure_managed_directory(parent)?;
    } else {
        fs::create_dir_all(parent)?;
    }
    let (temporary, mut file) = create_temporary_file(parent, &stem, "tmp", managed)?;
    let written = file.write_all(bytes).and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = native::replace_file(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

/// Reads a managed file. Under the managed root the file must not be a
/// reparse point and must be owned by SYSTEM, Administrators or the account
/// running this process; the check and the read use the same handle.
pub fn read_managed_file(path: &Path) -> io::Result<Vec<u8>> {
    if !is_within_managed_root(path) {
        return fs::read(path);
    }
    let mut file = native::open_trusted_file(path, true)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Reads a managed file like [`read_managed_file`], but under the managed
/// root accepts only SYSTEM or Administrators as its owner: for records a
/// privileged process acts on, which an unelevated session of the same
/// account must not be able to plant.
pub fn read_admin_owned_file(path: &Path) -> io::Result<Vec<u8>> {
    if !is_within_managed_root(path) {
        return fs::read(path);
    }
    let mut file = native::open_trusted_file(path, false)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Creates the host-wide named object `name` in the private namespace
/// [`HOST_NAMESPACE`], whose boundary holds the Administrators SID, and
/// returns what keeps it alive. Only a process whose token holds that SID
/// enabled can create or open the namespace, so a standard user can neither
/// create the object first nor hold it (a name in `Global\` could be created
/// first by anyone, with an access list of their choice). The object is
/// open to SYSTEM and Administrators only. `ResourceBusy` when it already
/// exists, that is when another process holds it; it goes away with the
/// last handle, so a process that dies releases it.
///
/// The namespace is machine-wide, not per session: a private namespace is
/// identified by its name and boundary only, and the boundary holds no
/// session number (a session would have to be added to it explicitly), so
/// the service in session 0 and an elevated client in a user session open
/// the same namespace and the same object, and exclude each other. A
/// cross-session check on a real machine is listed in
/// `docs/manual-intervention.md`.
#[cfg(windows)]
pub(crate) fn create_host_wide_object(name: &str) -> io::Result<HostWideObject> {
    native::create_host_wide_object(name)
}

/// Alias prefix and boundary name of the private namespace of
/// [`create_host_wide_object`].
#[cfg(windows)]
pub(crate) const HOST_NAMESPACE: &str = "AnixOps";

/// A host-wide object and the private namespace it lives in, both held
/// until dropped.
#[cfg(windows)]
pub(crate) struct HostWideObject {
    _object: std::os::windows::io::OwnedHandle,
    _namespace: native::Namespace,
}

#[cfg(windows)]
impl std::fmt::Debug for HostWideObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostWideObject")
    }
}

/// Creates a new file with a random name in the protected `directory` (made
/// protected first) and returns its path and a handle open for writing that
/// nobody else can open while it is held.
#[cfg(windows)]
pub(crate) fn create_managed_temporary_file(
    directory: &Path,
    stem: &str,
    extension: &str,
) -> io::Result<(PathBuf, File)> {
    ensure_managed_directory(directory)?;
    create_temporary_file(
        directory,
        stem,
        extension,
        is_within_managed_root(directory),
    )
}

fn create_temporary_file(
    directory: &Path,
    stem: &str,
    extension: &str,
    managed: bool,
) -> io::Result<(PathBuf, File)> {
    let mut last_error = None;
    for _ in 0..8 {
        let path = directory.join(format!(
            ".{stem}.{}.{:016x}.{extension}",
            std::process::id(),
            random_u64()?
        ));
        let created = if managed {
            native::create_protected_file(&path)
        } else {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
        };
        match created {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last_error = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("no free temporary file name")))
}

pub(crate) fn random_u64() -> io::Result<u64> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("the system random generator failed"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

#[cfg(not(windows))]
mod native {
    use super::*;

    pub(super) fn ensure_protected_directory(directory: &Path) -> io::Result<()> {
        fs::create_dir_all(directory)
    }

    pub(super) fn create_protected_file(path: &Path) -> io::Result<File> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
    }

    pub(super) fn open_trusted_file(path: &Path, allow_current_user: bool) -> io::Result<File> {
        let _ = allow_current_user;
        File::open(path)
    }

    pub(super) fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
        fs::rename(temporary, destination)
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_NOT_ALL_ASSIGNED,
        ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, LUID,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, CreateWellKnownSid, EqualSid, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetTokenInformation, IsWellKnownSid, LookupPrivilegeValueW,
        TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACL, DACL_SECURITY_INFORMATION,
        LUID_AND_ATTRIBUTES, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED,
        SE_TAKE_OWNERSHIP_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, GetFileInformationByHandle, MoveFileExW,
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::Threading::{
        AddSIDToBoundaryDescriptor, ClosePrivateNamespace, CreateBoundaryDescriptorW, CreateMutexW,
        CreatePrivateNamespaceW, DeleteBoundaryDescriptor, GetCurrentProcess,
        OpenPrivateNamespaceW, OpenProcessToken,
    };

    /// Owned by Administrators; SYSTEM and Administrators have full control,
    /// Users may read and list; nothing is inherited from `%ProgramData%`,
    /// and files and folders created inside inherit the same entries.
    const DIRECTORY_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
    /// The same entries for a file created inside a managed folder.
    const FILE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";

    /// A security descriptor from `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl SecurityDescriptor {
        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let text = wide_str(sddl);
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(descriptor))
        }

        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            }
        }

        fn dacl(&self) -> io::Result<*mut ACL> {
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl: *mut ACL = null_mut();
            if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            if present == 0 || dacl.is_null() {
                return Err(io::Error::other("the managed access list is missing"));
            }
            Ok(dacl)
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0) };
            }
        }
    }

    /// Owner and protection of an object, read with `GetSecurityInfo`.
    struct ObjectSecurity {
        owner_is_admin_or_system: bool,
        owner_is_current_user: bool,
        protected: bool,
    }

    fn object_security(file: &File) -> io::Result<ObjectSecurity> {
        let mut owner: PSID = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                raw(file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // Owns the descriptor `owner` points into.
        let descriptor = SecurityDescriptor(descriptor);
        let mut control = 0u16;
        let mut revision = 0u32;
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let owner_is_admin_or_system = !owner.is_null()
            && unsafe {
                IsWellKnownSid(owner, WinLocalSystemSid) != 0
                    || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            };
        let owner_is_current_user = !owner.is_null() && {
            let user = current_user()?;
            unsafe { EqualSid(owner, user_sid(&user)) != 0 }
        };
        Ok(ObjectSecurity {
            owner_is_admin_or_system,
            owner_is_current_user,
            protected: control & SE_DACL_PROTECTED != 0,
        })
    }

    pub(super) fn ensure_protected_directory(directory: &Path) -> io::Result<()> {
        if create_protected_directory(directory)? {
            return Ok(());
        }
        let security = object_security(&open_directory(directory, READ_CONTROL)?)?;
        if security.owner_is_admin_or_system && security.protected {
            return Ok(());
        }
        repair_directory(directory, security.owner_is_admin_or_system)?;
        let security = object_security(&open_directory(directory, READ_CONTROL)?)?;
        if !(security.owner_is_admin_or_system && security.protected) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the managed folder could not be protected",
            ));
        }
        // Folders below were created with the old inherited access list
        // (Users may create files in them); give them the protected one too.
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                // Nothing in the managed tree is a link; one found while
                // repairing was planted. Removing it removes the link only.
                let _ = fs::remove_dir(entry.path()).or_else(|_| fs::remove_file(entry.path()));
            } else if kind.is_dir() {
                ensure_protected_directory(&entry.path())?;
            }
        }
        Ok(())
    }

    /// Creates `directory` with the protected access list; `false` when it
    /// already exists.
    fn create_protected_directory(directory: &Path) -> io::Result<bool> {
        let descriptor = SecurityDescriptor::from_sddl(DIRECTORY_SDDL)?;
        let attributes = descriptor.attributes();
        let name = wide_path(directory);
        if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } != 0 {
            return Ok(true);
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_ALREADY_EXISTS {
            return Ok(false);
        }
        Err(io::Error::from_raw_os_error(error as i32))
    }

    /// Makes Administrators the owner (taking ownership when another account
    /// owns it) and sets the protected access list.
    fn repair_directory(directory: &Path, owner_trusted: bool) -> io::Result<()> {
        if !owner_trusted {
            let _privilege = EnabledPrivilege::enable(SE_TAKE_OWNERSHIP_NAME)?;
            let handle = open_directory(directory, READ_CONTROL | WRITE_OWNER)?;
            let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
            let status = unsafe {
                SetSecurityInfo(
                    raw(&handle),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    administrators.as_ptr() as PSID,
                    null_mut(),
                    null(),
                    null(),
                )
            };
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
        }
        let descriptor = SecurityDescriptor::from_sddl(DIRECTORY_SDDL)?;
        let dacl = descriptor.dacl()?;
        let handle = open_directory(directory, READ_CONTROL | WRITE_DAC)?;
        let status = unsafe {
            SetSecurityInfo(
                raw(&handle),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    /// Opens the folder itself (never what a link points to) and refuses a
    /// reparse point or anything that is not a folder.
    fn open_directory(directory: &Path, access: u32) -> io::Result<File> {
        let name = wide_path(directory);
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                access | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        let file = owned_file(handle)?;
        let attributes = file_attributes(&file)?;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "a managed folder is a link to somewhere else",
            ));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a managed folder is not a folder",
            ));
        }
        Ok(file)
    }

    pub(super) fn create_protected_file(path: &Path) -> io::Result<File> {
        let descriptor = SecurityDescriptor::from_sddl(FILE_SDDL)?;
        let attributes = descriptor.attributes();
        let name = wide_path(path);
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        owned_file(handle)
    }

    /// Opens a managed file for reading when it is not a link or a folder and
    /// SYSTEM or Administrators own it, or, with `allow_current_user`, the
    /// account running this process.
    pub(super) fn open_trusted_file(path: &Path, allow_current_user: bool) -> io::Result<File> {
        let name = wide_path(path);
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        let file = owned_file(handle)?;
        let attributes = file_attributes(&file)?;
        if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "a managed file is a link or a folder",
            ));
        }
        let security = object_security(&file)?;
        if !(security.owner_is_admin_or_system
            || (allow_current_user && security.owner_is_current_user))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "a managed file is owned by another account",
            ));
        }
        Ok(file)
    }

    /// SYSTEM and Administrators only; nothing for other accounts.
    const HOST_OBJECT_SDDL: &str = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)";

    /// A private namespace handle, closed when dropped.
    pub(crate) struct Namespace(*mut core::ffi::c_void);

    // The handle is only closed, from whichever thread drops it.
    unsafe impl Send for Namespace {}
    unsafe impl Sync for Namespace {}

    impl Drop for Namespace {
        fn drop(&mut self) {
            unsafe {
                ClosePrivateNamespace(self.0 as _, 0);
            }
        }
    }

    /// A boundary descriptor, deleted when dropped.
    struct Boundary(*mut core::ffi::c_void);

    impl Drop for Boundary {
        fn drop(&mut self) {
            unsafe { DeleteBoundaryDescriptor(self.0 as _) };
        }
    }

    /// Creates, or opens when another of our processes made it, the private
    /// namespace whose boundary holds the Administrators SID.
    fn host_namespace(attributes: &SECURITY_ATTRIBUTES) -> io::Result<Namespace> {
        let name = wide_str(HOST_NAMESPACE);
        let created = unsafe { CreateBoundaryDescriptorW(name.as_ptr(), 0) };
        if created.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut boundary = Boundary(created);
        let mut administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
        let mut handle = boundary.0 as _;
        let added =
            unsafe { AddSIDToBoundaryDescriptor(&mut handle, administrators.as_mut_ptr() as PSID) };
        boundary.0 = handle;
        if added == 0 {
            return Err(io::Error::last_os_error());
        }
        let namespace =
            unsafe { CreatePrivateNamespaceW(attributes, boundary.0 as _, name.as_ptr()) };
        if !namespace.is_null() {
            return Ok(Namespace(namespace));
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_ALREADY_EXISTS {
            return Err(namespace_error(error));
        }
        let namespace = unsafe { OpenPrivateNamespaceW(boundary.0 as _, name.as_ptr()) };
        if namespace.is_null() {
            return Err(namespace_error(unsafe { GetLastError() }));
        }
        Ok(Namespace(namespace))
    }

    /// A token without the Administrators SID enabled is refused the
    /// namespace: say so rather than "access denied".
    fn namespace_error(error: u32) -> io::Error {
        if error == ERROR_ACCESS_DENIED {
            return io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the host-wide namespace needs an elevated administrator",
            );
        }
        io::Error::from_raw_os_error(error as i32)
    }

    pub(super) fn create_host_wide_object(name: &str) -> io::Result<HostWideObject> {
        let descriptor = SecurityDescriptor::from_sddl(HOST_OBJECT_SDDL)?;
        let attributes = descriptor.attributes();
        let namespace = host_namespace(&attributes)?;
        let wide = wide_str(&format!("{HOST_NAMESPACE}\\{name}"));
        let handle = unsafe { CreateMutexW(&attributes, 0, wide.as_ptr()) };
        let error = unsafe { GetLastError() };
        if handle.is_null() {
            // Another process created it with an access list that leaves us
            // out, which also means it is held.
            if error == ERROR_ACCESS_DENIED {
                return Err(io::Error::new(
                    io::ErrorKind::ResourceBusy,
                    "the host-wide object is held by another process",
                ));
            }
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
        if error == ERROR_ALREADY_EXISTS {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "the host-wide object is held by another process",
            ));
        }
        Ok(HostWideObject {
            _object: handle,
            _namespace: namespace,
        })
    }

    pub(super) fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
        let temporary = wide_path(temporary);
        let destination = wide_path(destination);
        if unsafe {
            MoveFileExW(
                temporary.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn owned_file(handle: HANDLE) -> io::Result<File> {
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
    }

    fn file_attributes(file: &File) -> io::Result<u32> {
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(raw(file), &mut information) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(information.dwFileAttributes)
    }

    fn raw(file: &File) -> HANDLE {
        file.as_raw_handle() as HANDLE
    }

    /// The `TOKEN_USER` of this process, in a buffer aligned for it.
    fn current_user() -> io::Result<Vec<u64>> {
        let mut token: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
        let mut size = 0u32;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenUser,
                null_mut(),
                0,
                &mut size,
            )
        };
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenUser,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                size,
                &mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }

    fn user_sid(buffer: &[u64]) -> PSID {
        unsafe { (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid }
    }

    fn well_known_sid(kind: i32) -> io::Result<Vec<u64>> {
        // SECURITY_MAX_SID_SIZE is 68 bytes.
        let mut buffer = vec![0u64; 16];
        let mut size = (buffer.len() * size_of::<u64>()) as u32;
        if unsafe { CreateWellKnownSid(kind, null_mut(), buffer.as_mut_ptr() as PSID, &mut size) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }

    /// A privilege enabled on this process's token until dropped.
    struct EnabledPrivilege {
        token: OwnedHandle,
        luid: LUID,
    }

    impl EnabledPrivilege {
        fn enable(name: windows_sys::core::PCWSTR) -> io::Result<Self> {
            let mut token: HANDLE = null_mut();
            if unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    &mut token,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
            let mut luid = LUID {
                LowPart: 0,
                HighPart: 0,
            };
            if unsafe { LookupPrivilegeValueW(null(), name, &mut luid) } == 0 {
                return Err(io::Error::last_os_error());
            }
            adjust_privilege(&token, luid, SE_PRIVILEGE_ENABLED)?;
            Ok(Self { token, luid })
        }
    }

    impl Drop for EnabledPrivilege {
        fn drop(&mut self) {
            let _ = adjust_privilege(&self.token, self.luid, 0);
        }
    }

    fn adjust_privilege(token: &OwnedHandle, luid: LUID, attributes: u32) -> io::Result<()> {
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: attributes,
            }],
        };
        if unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle() as HANDLE,
                0,
                &privileges,
                0,
                null_mut(),
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // Succeeds without enabling anything when the token lacks it.
        if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
            return Err(io::Error::from_raw_os_error(ERROR_NOT_ALL_ASSIGNED as i32));
        }
        Ok(())
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn wide_str(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn scratch(name: &str) -> PathBuf {
            std::env::temp_dir().join(format!(
                "networkcore-managed-files-{name}-{}",
                std::process::id()
            ))
        }

        /// The protected folder really is protected, owned by Administrators
        /// and readable by the test (CI runs elevated, as the GUI does).
        #[test]
        fn protected_folders_and_files_get_the_managed_access_list() {
            let directory = scratch("protected");
            let _ = fs::remove_dir_all(&directory);
            assert!(create_protected_directory(&directory).expect("folder is created"));
            assert!(!create_protected_directory(&directory).expect("existing folder is kept"));
            let security =
                object_security(&open_directory(&directory, READ_CONTROL).unwrap()).unwrap();
            assert!(security.owner_is_admin_or_system);
            assert!(security.protected);

            let file_path = directory.join("file.json");
            let mut file = create_protected_file(&file_path).expect("file is created");
            file.write_all(b"{}").unwrap();
            drop(file);
            // CREATE_NEW never opens what is already there.
            assert_eq!(
                create_protected_file(&file_path).unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            let mut opened = open_trusted_file(&file_path, true).expect("own file is trusted");
            let mut text = String::new();
            opened.read_to_string(&mut text).unwrap();
            assert_eq!(text, "{}");
            drop(opened);
            let _ = fs::remove_dir_all(&directory);
        }

        /// A folder created with the inherited access list, as earlier
        /// versions left it, is reset to the protected one.
        #[test]
        fn an_inherited_folder_is_repaired() {
            let directory = scratch("inherited");
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir_all(directory.join("child")).unwrap();
            ensure_protected_directory(&directory).expect("folder is repaired");
            for folder in [directory.clone(), directory.join("child")] {
                let security =
                    object_security(&open_directory(&folder, READ_CONTROL).unwrap()).unwrap();
                assert!(security.owner_is_admin_or_system, "{}", folder.display());
                assert!(security.protected, "{}", folder.display());
            }
            let _ = fs::remove_dir_all(&directory);
        }

        /// A junction where a managed folder should be is never followed.
        #[test]
        fn a_junction_is_refused() {
            let directory = scratch("junction");
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir_all(directory.join("target")).unwrap();
            let link = directory.join("link");
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(directory.join("target"))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("cmd runs");
            assert!(status.success(), "the junction is created");
            let error = open_directory(&link, READ_CONTROL).expect_err("junction is refused");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            let _ = fs::remove_dir(&link);
            let _ = fs::remove_dir_all(&directory);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "networkcore-managed-write-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        directory
    }

    #[test]
    fn atomic_write_never_reuses_a_planted_temporary_file() {
        let directory = scratch("planted");
        fs::create_dir_all(&directory).unwrap();
        let target = directory.join("managed-config.json");
        // What earlier versions used as the fixed temporary name.
        let planted = directory.join("managed-config.json.tmp");
        fs::write(&planted, b"planted").unwrap();
        write_managed_file_atomic(&target, b"{\"ok\":true}").expect("write succeeds");
        assert_eq!(fs::read(&target).unwrap(), b"{\"ok\":true}");
        assert_eq!(fs::read(&planted).unwrap(), b"planted");
        // No temporary file is left behind.
        let leftovers = fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
            .count();
        assert_eq!(leftovers, 0);
        write_managed_file_atomic(&target, b"second").expect("replace succeeds");
        assert_eq!(read_managed_file(&target).unwrap(), b"second");
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn temporary_files_are_created_exclusively_with_random_names() {
        let directory = scratch("random");
        fs::create_dir_all(&directory).unwrap();
        let (first, _a) = create_temporary_file(&directory, "task", "xml", false).unwrap();
        let (second, _b) = create_temporary_file(&directory, "task", "xml", false).unwrap();
        assert_ne!(first, second);
        assert!(first
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".xml"));
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn managed_root_containment_rejects_parent_components() {
        let root = windows_managed_root_directory();
        assert!(is_within_managed_root(&root));
        assert!(is_within_managed_root(
            &root.join("NetworkCore").join("x.json")
        ));
        assert!(!is_within_managed_root(
            &root.join("..").join("Other").join("x.json")
        ));
        assert!(!is_within_managed_root(
            &std::env::temp_dir().join("x.json")
        ));
    }
}
