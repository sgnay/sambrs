#![warn(clippy::pedantic)]

//! A tiny ergonomic wrapper around `WNetAddConnection2W` and `WNetCancelConnection2W`. The goal is
//! to offer an easy to use interface to connect to SMB network shares on Windows.
//!
//! Sam -> SMB -> Rust -> Samba is taken!? -> sambrs
//!
//! # How To
//!
//! Instantiate an `SmbShare` with an optional local Windows mount point and establish a
//! connection.
//!
//! When calling the connect method, you have the option to persist the connection across user
//! login sessions and to enable interactive mode. Interactive mode will block until the user
//! either provides a correct password or cancels, resulting in a `Canceled` error.
//!
//! ```no_run
//! use sambrs::SmbShare;
//!
//! let share = SmbShare::new(r"\\server\share", "user", "pass", Some('D'));
//!
//! match share.connect(false, false) {
//!     Ok(()) => println!("Connected successfully!"),
//!     Err(e) => eprintln!("Failed to connect: {}", e),
//! }
//!
//! // use std::fs as if D:\ was a local directory
//! dbg!(std::fs::metadata(r"D:\").unwrap().is_dir());
//! ```

mod error;

pub use error::{Error, Result};
// (Previously used CString for ANSI APIs; migration to Unicode uses wide strings.)
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use tracing::{debug, error, trace};
use windows_sys::Win32::Foundation::{FALSE, TRUE};
use windows_sys::Win32::NetworkManagement::WNet;

pub struct SmbShare {
    share: String,
    username: String,
    password: String,
    mount_on: Option<char>,
}

/// Convert a Rust string slice to a wide (UTF-16) NUL-terminated Vec<u16> suitable for Win32 APIs.
fn to_wide_null(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = OsStr::new(s).encode_wide().collect();
    v.push(0);
    v
}

/// Map Win32 error codes returned by `WNet`* functions into the local Error enum.
fn map_win32_error(code: u32) -> Result<()> {
    use windows_sys::Win32::Foundation::{
        NO_ERROR,
        ERROR_ACCESS_DENIED,
        ERROR_ALREADY_ASSIGNED,
        ERROR_BAD_DEV_TYPE,
        ERROR_BAD_DEVICE,
        ERROR_BAD_NET_NAME,
        ERROR_BAD_PROFILE,
        ERROR_BAD_PROVIDER,
        ERROR_BAD_USERNAME,
        ERROR_BUSY,
        ERROR_CANCELLED,
        ERROR_CANNOT_OPEN_PROFILE,
        ERROR_DEVICE_ALREADY_REMEMBERED,
        ERROR_DEVICE_IN_USE,
        ERROR_EXTENDED_ERROR,
        ERROR_INVALID_ADDRESS,
        ERROR_INVALID_PARAMETER,
        ERROR_INVALID_PASSWORD,
        ERROR_LOGON_FAILURE,
        ERROR_NO_NET_OR_BAD_PATH,
        ERROR_NO_NETWORK,
        ERROR_NOT_CONNECTED,
        ERROR_OPEN_FILES,
    };

    match code {
        NO_ERROR => Ok(()),
        ERROR_ACCESS_DENIED => Err(Error::AccessDenied),
        ERROR_ALREADY_ASSIGNED => Err(Error::AlreadyAssigned),
        ERROR_BAD_DEV_TYPE => Err(Error::BadDevType),
        ERROR_BAD_DEVICE => Err(Error::BadDevice),
        ERROR_BAD_NET_NAME => Err(Error::BadNetName),
        ERROR_BAD_PROFILE => Err(Error::BadProfile),
        ERROR_BAD_PROVIDER => Err(Error::BadProvider),
        ERROR_BAD_USERNAME => Err(Error::BadUsername),
        ERROR_BUSY => Err(Error::Busy),
        ERROR_CANCELLED => Err(Error::Cancelled),
        ERROR_CANNOT_OPEN_PROFILE => Err(Error::CannotOpenProfile),
        ERROR_DEVICE_ALREADY_REMEMBERED => Err(Error::DeviceAlreadyRemembered),
        ERROR_EXTENDED_ERROR => Err(Error::ExtendedError),
        ERROR_INVALID_ADDRESS => Err(Error::InvalidAddress),
        ERROR_INVALID_PARAMETER => Err(Error::InvalidParameter),
        ERROR_INVALID_PASSWORD => Err(Error::InvalidPassword),
        ERROR_LOGON_FAILURE => Err(Error::LogonFailure),
        ERROR_NO_NET_OR_BAD_PATH => Err(Error::NoNetOrBadPath),
        ERROR_NO_NETWORK => Err(Error::NoNetwork),
        ERROR_NOT_CONNECTED => Err(Error::NotConnected),
        ERROR_OPEN_FILES => Err(Error::OpenFiles),
        ERROR_DEVICE_IN_USE => Err(Error::DeviceInUse),
        _ => Err(Error::Other),
    }
}

impl SmbShare {
    /// Create an `SmbShare` representation to connect to.
    ///
    /// Optionally specify `mount_on` to map the SMB share to a local device. Otherwise it will be
    /// a deviceless connection. Case insensitive.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let share = sambrs::SmbShare::new(r"\\server.local\share", r"LOGONDOMAIN\user", "pass", None);
    /// ```
    pub fn new(
        share: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        mount_on: Option<char>,
    ) -> Self {
        Self {
            share: share.into(),
            username: username.into(),
            password: password.into(),
            mount_on,
        }
    }

    /// Connect to the SMB share. Connecting multiple times works fine in deviceless mode but fails
    /// with a local mount point.
    ///
    /// - `persist` will remember the connection and restore when the user logs off and on again. No-op
    ///   if `mount_on` is `None`
    /// - `interactive` will prompt the user for a password instead of failing with `Error::InvalidPassword`
    ///
    /// # Some excerpts from the [Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w)
    ///
    /// `persist` (`CONNECT_UPDATE_PROFILE`): The network resource connection should be remembered. If this bit
    /// flag is set, the operating system automatically attempts to restore the connection when the
    /// user logs on.
    ///
    /// The operating system remembers only successful connections that redirect local devices. It does
    /// not remember connections that are unsuccessful or deviceless connections. (A deviceless
    /// connection occurs when the `lpLocalName` member is NULL or points to an empty string.)
    ///
    /// If this bit flag is clear, the operating system does not try to restore the connection when the
    /// user logs on.
    ///
    /// `!persist` (`CONNECT_TEMPORARY`): The network resource connection should not be remembered. If this flag is
    /// set, the operating system will not attempt to restore the connection when the user logs on
    /// again.
    ///
    /// `interactive` (`CONNECT_INTERACTIVE`): If this flag is set, the operating system may interact with the user for
    /// authentication purposes.
    ///
    /// # Errors
    /// This method will error if Windows is unable to connect to the SMB share.
    pub fn connect(&self, persist: bool, interactive: bool) -> Result<()> {
        // Prepare optional local name as wide string
        let local_name_buf = self.mount_on.map(|ln| to_wide_null(format!("{ln}:") .as_str()));
        let local_name = local_name_buf
            .as_ref()
            .map_or(std::ptr::null_mut(), |v| v.as_ptr().cast_mut());

        let mut flags = 0u32;

        if persist && self.mount_on.is_some() {
            flags |= WNet::CONNECT_UPDATE_PROFILE;
        } else {
            flags |= WNet::CONNECT_TEMPORARY;
        }

        if interactive {
            flags |= WNet::CONNECT_INTERACTIVE;
        }

        debug!("Connection flags: {flags:#?}");

        // Convert strings to wide (UTF-16) with NUL terminator
    let share_w = to_wide_null(&self.share);
    let username_w = to_wide_null(&self.username);
    let password_w = to_wide_null(&self.password);

        // https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/ns-winnetwk-netresourcew
        let mut netresource = WNet::NETRESOURCEW {
            dwDisplayType: 0, // ignored by WNetAddConnection2W
            dwScope: 0,       // ignored by WNetAddConnection2W
            dwType: WNet::RESOURCETYPE_DISK,
            dwUsage: 0, // ignored by WNetAddConnection2W
            lpLocalName: local_name,
            lpRemoteName: share_w.as_ptr().cast_mut(),
            lpComment: std::ptr::null_mut(), // ignored by WNetAddConnection2W
            lpProvider: std::ptr::null_mut(), // Microsoft docs: You should set this member only if you know the network provider you want to use.
                                               // Otherwise, let the operating system determine which provider the network name maps to.
        };

        trace!("Trying to connect to {}", self.share);

        // https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w
        let connection_result = unsafe {
            let username = username_w.as_ptr();
            let password = password_w.as_ptr();
            WNet::WNetAddConnection2W(
                std::ptr::from_mut::<WNet::NETRESOURCEW>(&mut netresource),
                password,
                username,
                flags,
            )
        };

        debug!("Connection result: {connection_result:#?}");

        let connection_result = map_win32_error(connection_result);

        match connection_result {
            Ok(()) => {
                trace!("Successfully connected");
            }
            Err(ref e) => error!("Connection failed: {e}"),
    }

        connection_result
    }

    /// Disconnect from the SMB share.
    ///
    /// `persist` (`CONNECT_UPDATE_PROFILE`): The system updates the user profile with the
    /// information that the connection is no longer a persistent one. The system will not restore
    /// this connection during subsequent logon operations. (Disconnecting resources using remote
    /// names has no effect on persistent connections.)
    ///
    /// `force`: Specifies whether the disconnection should occur if there are open files or jobs
    /// on the connection. If this parameter is FALSE, the function fails if there are open files
    /// or jobs.
    ///
    /// # Errors
    /// This method will return an error if Windows is unable to disconnect from the smb share.
    pub fn disconnect(&self, persist: bool, force: bool) -> Result<()> {
        let resource_to_disconnect_w = match self.mount_on {
            Some(ln) => to_wide_null(&format!("{ln}:")),
            None => to_wide_null(&self.share),
        };

        let force = if force { TRUE } else { FALSE };

        let persist = if persist && self.mount_on.is_some() {
            WNet::CONNECT_UPDATE_PROFILE
        } else {
            0
        };

        let disconnect_result = unsafe {
            WNet::WNetCancelConnection2W(resource_to_disconnect_w.as_ptr().cast_mut(), persist, force)
        };

        debug!("Disconnect result: {disconnect_result:#?}");

        let disconnect_result = map_win32_error(disconnect_result);

        match disconnect_result {
            Ok(()) => trace!("Successfully disconnected"),
            Err(ref e) => error!("Disconnect failed: {e}"),
        }

        disconnect_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: propper integration test setup

    const VALID_SHARE: &str = r"PUTYOURSHARE";
    const CORRECT_USERNAME: &str = r"PUTYOURUSER";
    const CORRECT_PASSWORD: &str = r"PUTYOURPASS";

    const WRONG_SHARE: &str = r"\\thisisnotashare.local\Share-Name";
    const WRONG_PASSWORD: &str = r"pass";

    // I really wanted to assert against a specific error, but lovely Windows sometimes returns
    // `LogonFailure` and sometimes `InvalidPassword`.
    #[test]
    #[ignore]
    fn sad_non_interactive_does_not_prompt_and_returns_error() {
        let share = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, WRONG_PASSWORD, None);
        let connection = share.connect(false, false);
        assert!(connection.is_err());
        if let Err(e) = connection {
            assert!(e == Error::InvalidPassword || e == Error::LogonFailure);
        }
    }

    #[test]
    #[ignore]
    fn sad_non_existent_share() {
        let share = SmbShare::new(WRONG_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, None);
        let connection = share.connect(false, false);
        assert!(connection.is_err());
        if let Err(e) = connection {
            assert_eq!(e, Error::BadNetName);
        }
    }

    #[test]
    #[ignore]
    fn happy_mount_on_works_and_does_not_persist() {
        let share = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, Some('s'));
        let connection = share.connect(false, false);
        assert!(connection.is_ok());
        assert!(std::path::Path::new(r"s:\").is_dir());
        let disconnect = share.disconnect(false, false);
        assert!(disconnect.is_ok());
    }

    #[test]
    #[ignore]
    fn happy_deviceless_works() {
        let share = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, None);
        let connection = share.connect(false, false);
        assert!(connection.is_ok());
        assert!(std::path::Path::new(VALID_SHARE).is_dir());
        let disconnect = share.disconnect(false, false);
        assert!(disconnect.is_ok());
    }

    #[test]
    #[ignore]
    fn happy_deviceless_reconnecting_is_fine() {
        let share = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, None);
        let connection = share.connect(false, false);
        assert!(connection.is_ok());
        let connection = share.connect(false, false);
        assert!(connection.is_ok());
        assert!(std::path::Path::new(VALID_SHARE).is_dir());
        let disconnect = share.disconnect(false, false);
        assert!(disconnect.is_ok());
    }

    #[test]
    #[ignore]
    fn sad_mounted_reconnecting_returns_already_assigned_error() {
        let share = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, Some('s'));
        let connection = share.connect(false, false);
        assert!(connection.is_ok());
        assert!(std::path::Path::new(r"s:\").is_dir());
        let connection = share.connect(false, false);
        assert!(connection.is_err());
        if let Err(e) = connection {
            assert_eq!(e, Error::AlreadyAssigned);
        }
        let disconnect = share.disconnect(false, false);
        assert!(disconnect.is_ok());
    }

    #[test]
    #[ignore]
    fn happy_connecting_multiple_letters_to_same_share_works() {
        let share_one = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, Some('s'));
        let connection1 = share_one.connect(false, false);
        assert!(connection1.is_ok());
        let share_two = SmbShare::new(VALID_SHARE, CORRECT_USERNAME, CORRECT_PASSWORD, Some('t'));
        let connection2 = share_two.connect(false, false);
        assert!(connection2.is_ok());
        assert!(std::path::Path::new(r"s:\").is_dir());
        assert!(std::path::Path::new(r"t:\").is_dir());
        let share_one_disconnect = share_one.disconnect(false, false);
        assert!(share_one_disconnect.is_ok());
        assert!(!std::path::Path::new(r"s:\").is_dir());
        let share_two_disconnect = share_two.disconnect(false, false);
        assert!(share_two_disconnect.is_ok());
        assert!(!std::path::Path::new(r"t:\").is_dir());
    }

    // Unit tests for helpers that don't require SMB environment
    #[test]
    fn to_wide_null_has_nul_and_length() {
        let s = "abc";
        let w = to_wide_null(s);
        assert_eq!(w.len(), 4);
        assert_eq!(w[3], 0);
    }

    #[test]
    fn map_win32_error_maps_known_codes() {
        use windows_sys::Win32::Foundation::NO_ERROR;
        assert!(map_win32_error(NO_ERROR).is_ok());
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
        assert_eq!(map_win32_error(ERROR_ACCESS_DENIED).unwrap_err(), Error::AccessDenied);
    }
}
