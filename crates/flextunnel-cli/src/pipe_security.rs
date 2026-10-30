//! Owner-only control pipes on Windows. Pipe names are one machine-wide
//! namespace and the default pipe security descriptor grants Everyone read
//! access, so the client session creates every pipe instance with an explicit
//! descriptor owned by, and only accessible to, the current user; and an
//! attaching command refuses a pipe another user owns — one that user could
//! have created first, while the client was stopped, to receive a `client nc`
//! stream or feed `client control` a fake status.

use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// This process's user SID in string form (`S-1-5-21-…`).
pub fn current_user_sid() -> io::Result<String> {
    // SAFETY: the token handle is closed on every path, and the TOKEN_USER is
    // read from a buffer of the size and (u64) alignment the call asked for.
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        let err = io::Error::last_os_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(err);
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_to_string(user.User.Sid)
    }
}

/// Create one pipe instance owned by, and accessible only to, `sid`. The owner
/// is set explicitly so an elevated client (whose default owner would be the
/// Administrators group) still passes [`check_owner`].
pub fn create_owner_only(
    options: &ServerOptions,
    name: &str,
    sid: &str,
) -> io::Result<NamedPipeServer> {
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;;GA;;;{sid})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: the descriptor outlives the create call and is freed once.
    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let pipe = options.create_with_security_attributes_raw(name, (&raw mut attrs).cast());
        LocalFree(sd);
        pipe
    }
}

/// Fail unless `pipe` is owned by `sid`.
pub fn check_owner(pipe: &impl AsRawHandle, sid: &str) -> io::Result<()> {
    // SAFETY: the owner SID points into the returned descriptor, which is
    // freed only after the SID has been converted.
    let owner = unsafe {
        let mut owner: PSID = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let err = GetSecurityInfo(
            pipe.as_raw_handle() as HANDLE,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        );
        if err != 0 {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        let owner = sid_to_string(owner);
        LocalFree(sd);
        owner?
    };
    if owner == sid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the control pipe is owned by another user ({owner}), not this one ({sid})"),
        ))
    }
}

/// # Safety
/// `sid` must point to a valid SID.
unsafe fn sid_to_string(sid: PSID) -> io::Result<String> {
    // SAFETY: on success the call returns a NUL-terminated wide string that
    // is freed once, after it is copied.
    unsafe {
        let mut wide = null_mut();
        if ConvertSidToStringSidW(sid, &mut wide) == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = (0..).take_while(|&i| *wide.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(wide, len));
        LocalFree(wide.cast());
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_sid_is_a_sid_string() {
        assert!(current_user_sid().unwrap().starts_with("S-1-"));
    }
}
