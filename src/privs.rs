use windows_sys::Win32::{
    Foundation::{GetLastError, LUID, STATUS_SUCCESS, UNICODE_STRING},
    Security::{
        Authentication::Identity::{
            LsaAddAccountRights, LsaEnumerateAccountRights, LsaEnumerateAccountsWithUserRight,
            LsaNtStatusToWinError, LsaOpenPolicy, LsaRemoveAccountRights,
            LSA_ENUMERATION_INFORMATION, LSA_HANDLE,
        },
        LookupPrivilegeNameW, LookupPrivilegeValueW,
    },
    System::WindowsProgramming::{RtlInitUnicodeString, OBJECT_ATTRIBUTES},
};

use crate::{
    encode_string_to_wide,
    users::{get_user_by_sid, get_user_sid, sid_to_string_sid},
    MAX_NAME, POLICY_ALL_ACCESS,
};

/// Add account privilege / right to the specified user account.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::privs::add_user_privilege;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let privilege = "SeShutdownPrivilege";
///     if let Err(err) = add_user_privilege(username, privilege) {
///         log::error!("Error: {} - {}\n", err, win_err_text(err));
///         return;
///     }
///}
/// ```
pub fn add_user_privilege(username: &str, privilege: &str) -> Result<(), u32> {
    let mut user_sid = get_user_sid(username)?;
    let lsa_policy_handle = get_lsa_policy_handle()?;

    let privilege_wide_nul = encode_string_to_wide(privilege);
    let mut privilege_unicode = unsafe { std::mem::zeroed::<UNICODE_STRING>() };
    unsafe {
        RtlInitUnicodeString(&mut privilege_unicode, privilege_wide_nul.as_ptr());
        let ntstatus = LsaAddAccountRights(
            lsa_policy_handle,
            user_sid.as_mut_ptr() as *mut std::ffi::c_void,
            &privilege_unicode,
            1,
        );

        if ntstatus != STATUS_SUCCESS {
            return Err(LsaNtStatusToWinError(ntstatus));
        }
    }

    Ok(())
}

/// Remove account privilege / right from the specified user account.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::privs::delete_user_privilege;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let privilege = "SeShutdownPrivilege";
///     if let Err(err) = delete_user_privilege(username, privilege) {
///         log::error!("Error: {} - {}\n", err, win_err_text(err));
///         return;
///     }
///}
/// ```
pub fn delete_user_privilege(username: &str, privilege: &str) -> Result<(), u32> {
    let mut user_sid = get_user_sid(username)?;
    let lsa_policy_handle = get_lsa_policy_handle()?;

    let privilege_wide_nul = encode_string_to_wide(privilege);
    let mut privilege_unicode = unsafe { std::mem::zeroed::<UNICODE_STRING>() };

    unsafe {
        RtlInitUnicodeString(&mut privilege_unicode, privilege_wide_nul.as_ptr());

        let ntstatus = LsaRemoveAccountRights(
            lsa_policy_handle,
            user_sid.as_mut_ptr() as *mut std::ffi::c_void,
            0,
            &privilege_unicode,
            1,
        );

        if ntstatus != STATUS_SUCCESS {
            return Err(LsaNtStatusToWinError(ntstatus));
        }
    }

    Ok(())
}

/// Returns a LUID name by specified privilege.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::privs::get_luid_by_priv_name;
///
/// fn main() {
///     let privilege = "SeDebugPrivilege";
///     let privilege_luid = get_luid_by_priv_name(privilege).unwrap();
///}
/// ```
pub fn get_luid_by_priv_name(privilege: &str) -> Result<LUID, u32> {
    let privilege_wide_nul = crate::encode_string_to_wide(privilege);
    let mut privilege_luid = unsafe { std::mem::zeroed::<LUID>() };
    unsafe {
        if LookupPrivilegeValueW(
            std::ptr::null_mut(),
            privilege_wide_nul.as_ptr(),
            &mut privilege_luid,
        ) == 0
        {
            return Err(GetLastError());
        }
    }

    Ok(privilege_luid)
}

/// Returns a privilege name by specified LUID.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::privs::{get_luid_by_priv_name, get_priv_name_by_luid};
///
/// fn main() {
///     let privilege = "SeDebugPrivilege";
///     let privilege_luid = get_luid_by_priv_name(privilege).unwrap();
///     let privilege_again = get_priv_name_by_luid(privilege_luid).unwrap();
///     println!("Priv name: {}", privilege_again)
///}
/// ```
#[allow(dead_code)]
pub fn get_priv_name_by_luid(priv_luid: LUID) -> Result<String, u32> {
    let mut priv_name: Vec<u16> = vec![0; MAX_NAME as usize];
    let mut priv_name_len = priv_name.len() as u32;

    unsafe {
        if LookupPrivilegeNameW(
            std::ptr::null_mut(),
            &priv_luid,
            priv_name.as_mut_ptr(),
            &mut priv_name_len,
        ) == 0
        {
            return Err(GetLastError());
        }
    }

    Ok(String::from_utf16_lossy(&priv_name))
}

/// Returns a list of user sids with the specified privilege (searching by account right will not work).
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::privs::get_account_sids_by_privilege;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let privilege = "SeImpersonatePrivilege";
///     let sids = match get_account_sids_by_privilege(privilege) {
///         Ok(sids) => sids,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///
///     for sid in sids {
///         println!("  {}", sid);
///     }
///}
/// ```
pub fn get_account_sids_by_privilege(privilege: &str) -> Result<Vec<String>, u32> {
    let mut user_sids = Vec::<String>::new();
    let usernames = get_users_by_privilege(privilege)?;
    for i in 0..usernames.len() {
        let mut user_sid = get_user_sid(&usernames[i])?;
        user_sids.push(sid_to_string_sid(
            user_sid.as_mut_ptr() as *mut std::ffi::c_void
        )?);
    }

    Ok(user_sids)
}

/// Returns a list of users with the specified privilege (searching by account right will not work).
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::privs::get_users_by_privilege;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let privilege = "SeDebugPrivilege";
///     let accounts = match get_users_by_privilege(privilege) {
///         Ok(accounts) => accounts,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///
///     for account in accounts {
///         println!("  {}", account);
///     }
///}
/// ```
pub fn get_users_by_privilege(privilege: &str) -> Result<Vec<String>, u32> {
    let lsa_policy_handle = get_lsa_policy_handle()?;
    let privilege_wide_nul = encode_string_to_wide(privilege);
    let mut privilege_unicode = unsafe { std::mem::zeroed::<UNICODE_STRING>() };
    let mut buffer: *mut std::ffi::c_void = std::ptr::null_mut();
    let lsa_enum_infos = unsafe {
        RtlInitUnicodeString(&mut privilege_unicode, privilege_wide_nul.as_ptr());

        let mut cound_returned: u32 = 0;
        let ntstatus = LsaEnumerateAccountsWithUserRight(
            lsa_policy_handle,
            &privilege_unicode,
            &mut buffer,
            &mut cound_returned,
        );

        if ntstatus != STATUS_SUCCESS {
            return Err(LsaNtStatusToWinError(ntstatus));
        }

        std::slice::from_raw_parts(
            buffer as *const LSA_ENUMERATION_INFORMATION,
            cound_returned as usize,
        )
    };

    let mut users = Vec::<String>::new();
    lsa_enum_infos.iter().for_each(|lsa_enum_info| {
        if let Ok(username) = get_user_by_sid(lsa_enum_info.Sid) {
            users.push(username);
        };
    });

    Ok(users)
}

/// Returns a list of privileges / rights of the specified user account.
///
/// Pay attention - inherited from group privileges won't displayed. (Ex.: privs from Administrators)
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::privs::get_user_privileges;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let privileges = match get_user_privileges(username) {
///         Ok(privileges) => privileges,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///
///     for privilege in privileges {
///         println!("  {}", privilege);
///     }
///}
/// ```
pub fn get_user_privileges(username: &str) -> Result<Vec<String>, u32> {
    let mut user_sid = get_user_sid(username)?;
    let lsa_policy_handle = get_lsa_policy_handle()?;

    let mut ptr_privileges_unicode = std::ptr::null_mut();
    let mut privileges_count = 0;

    let privileges_unicode = unsafe {
        let ntstatus = LsaEnumerateAccountRights(
            lsa_policy_handle,
            user_sid.as_mut_ptr() as *mut std::ffi::c_void,
            &mut ptr_privileges_unicode,
            &mut privileges_count,
        );

        /*
            If no account rights are found or if the function fails for any other reason,
            the function returns an NTSTATUS code such as FILE_NOT_FOUND (2 code).
        */
        let win_err = LsaNtStatusToWinError(ntstatus);
        if win_err == 2 {
            return Ok(Vec::new());
        }

        if ntstatus != STATUS_SUCCESS {
            return Err(win_err);
        }

        std::slice::from_raw_parts(ptr_privileges_unicode, privileges_count as usize)
    };

    let mut privileges = Vec::<String>::new();

    privileges_unicode.iter().for_each(|privilege_unicode| {
        privileges.push(unsafe { crate::unicode_string_to_string(*privilege_unicode) });
    });

    return Ok(privileges);
}

/// Returns LSA Policy handle.
///
/// If failed - returns Windows error.
fn get_lsa_policy_handle() -> Result<LSA_HANDLE, u32> {
    let mut obj_attrs = unsafe { std::mem::zeroed::<OBJECT_ATTRIBUTES>() };
    let mut lsa_handle: LSA_HANDLE = 0;
    unsafe {
        let ntstatus = LsaOpenPolicy(
            std::ptr::null_mut(),
            &mut obj_attrs,
            POLICY_ALL_ACCESS,
            &mut lsa_handle,
        );

        if ntstatus != STATUS_SUCCESS {
            return Err(LsaNtStatusToWinError(ntstatus));
        }
    }

    Ok(lsa_handle)
}
