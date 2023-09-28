use windows_sys::Win32::{
    Foundation::GetLastError,
    NetworkManagement::NetManagement::{
        NERR_Success, NetUserAdd, NetUserDel, NetUserEnum, NetUserGetInfo, NetUserSetInfo,
        FILTER_NORMAL_ACCOUNT, MAX_PREFERRED_LENGTH, UF_NORMAL_ACCOUNT, UF_SCRIPT, USER_INFO_0,
        USER_INFO_1, USER_PRIV_USER, USER_INFO_4, UF_ACCOUNTDISABLE,
    },
    Security::{
        Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
        GetLengthSid, IsValidSid, LookupAccountNameW, LookupAccountSidW,
    },
};

use crate::{MAX_NAME, decode_wide_nul_to_string};

/// Create new local user account with provided password.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::add_user;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let password = "P@ssw0rd123!!!";
///     let description = Some("Some account description".to_owned());
///     if let Err(err) = add_user(username, password, &description) {
///         log::error!("Error: {} - {}\n", err, win_err_text(err));
///         return;
///     }
///}
/// ```
pub fn add_user(username: &str, password: &str, description: &Option<String>) -> Result<(), u32> {
    let mut user_info = unsafe { std::mem::zeroed::<USER_INFO_1>() };
    let mut wide_username_nul = crate::encode_string_to_wide(username.clone());
    let mut wide_password_nul = crate::encode_string_to_wide(password);

    let mut wide_description_nul: Vec<u16>;
    if let Some(description) = description {
        wide_description_nul = crate::encode_string_to_wide(description);
        user_info.usri1_comment = wide_description_nul.as_mut_ptr();
    }

    user_info.usri1_name = wide_username_nul.as_mut_ptr();
    user_info.usri1_password = wide_password_nul.as_mut_ptr();
    user_info.usri1_priv = USER_PRIV_USER;
    user_info.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    user_info.usri1_script_path = std::ptr::null_mut();

    unsafe {
        let rc = NetUserAdd(
            std::ptr::null_mut(),
            1,
            &user_info as *const _ as *const u8,
            std::ptr::null_mut(),
        );
        if rc != NERR_Success {
            return Err(rc);
        }
    }

    Ok(())
}

/// Get all user accounts existing in the system.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::get_users;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let usernames = match get_users() {
///         Ok(usernames) => usernames,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///
///     for username in usernames {
///         println!("  {}", username);
///     }
///}
/// ```
pub fn get_users() -> Result<Vec<String>, u32> {
    let servername = std::ptr::null_mut();
    let level = 0; // Return only account names
    let mut buf_ptr = std::ptr::null_mut::<u8>();
    let mut entries_read = 0;
    let mut total_entries = 0;
    let mut resume_handle = 0;

    unsafe {
        let rc = NetUserEnum(
            servername,
            level,
            FILTER_NORMAL_ACCOUNT,
            &mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume_handle,
        );
        if rc != NERR_Success {
            return Err(rc);
        }
    }

    let accounts_slice = unsafe {
        std::slice::from_raw_parts(
            buf_ptr as *const u8 as *const USER_INFO_0,
            entries_read as usize,
        )
    };

    let mut accounts = Vec::<String>::with_capacity(entries_read as usize);
    for account in accounts_slice {
        accounts.push(crate::decode_wide_nul_to_string(account.usri0_name).unwrap());
    }

    Ok(accounts)
}

/// Changes password for existing user account.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::change_user_password;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let password = "New_!P@ssw0rd123!!!";
///     if let Err(err) = change_user_password(username, password) {
///         log::error!("Error: {} - {}\n", err, win_err_text(err));
///         return;
///     }
///}
/// ```
pub fn change_user_password(username: &str, password: &str) -> Result<(), u32> {
    let wide_username_nul = crate::encode_string_to_wide(username);
    let mut wide_password_nul = crate::encode_string_to_wide(password);
    let mut new_user_info_buf = std::ptr::null_mut::<u8>();
    unsafe {
        let rc = NetUserGetInfo(
            std::ptr::null_mut(),
            wide_username_nul.as_ptr(),
            1,
            &mut new_user_info_buf,
        );
        if rc != NERR_Success {
            return Err(rc);
        }
    }

    let new_user_info = new_user_info_buf as *mut USER_INFO_1;
    unsafe {
        (*new_user_info).usri1_password = wide_password_nul.as_mut_ptr();
    }

    unsafe {
        let rc = NetUserSetInfo(
            std::ptr::null_mut(),
            wide_username_nul.as_ptr(),
            1,
            new_user_info_buf,
            std::ptr::null_mut(),
        );
        if rc != NERR_Success {
            return Err(rc);
        }
    }

    Ok(())
}

/// Delete local user account.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::delete_user;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     if let Err(err) = delete_user(username) {
///         log::error!("Error: {} - {}\n", err, win_err_text(err));
///         return;
///     }
///}
/// ```
pub fn delete_user(username: &str) -> Result<(), u32> {
    let mut wide_username_nul = crate::encode_string_to_wide(username.clone());
    unsafe {
        let rc = NetUserDel(std::ptr::null_mut(), wide_username_nul.as_mut_ptr());
        if rc != NERR_Success {
            return Err(rc);
        }
    }

    Ok(())
}

/// Get detailed user account information (USER_INFO_4 struct).
/// 
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::get_user_detailed;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let account = match get_user_detailed(username) {
///         Ok(account) => account,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///}
/// ```
pub fn get_user_detailed(username: &str) -> Result<USER_INFO_4, u32> {
    let wide_username_nul = crate::encode_string_to_wide(username.clone());
    let mut user_info_buf = std::ptr::null_mut::<u8>();

    unsafe {
        let rc = NetUserGetInfo(
            std::ptr::null_mut(),
            wide_username_nul.as_ptr(),
            4,                              // USER_INFO_4
            &mut user_info_buf,
        );
        if rc != NERR_Success {
            return Err(rc);
        }
    }

    let account = user_info_buf as *mut USER_INFO_4;

    Ok(
        unsafe { *account }
    )
}

/// Print detailed information about specified user account.
/// 
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::print_user_detailed;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     if let Err(err) = print_user_detailed(username) {
///         log::error!("Error: {} - {}\n", err, win_err_text(err));
///         return;
///     }
///}
/// ```
pub fn print_user_detailed(username: &str) -> Result<(), u32> {
    let account = get_user_detailed(username)?;
    let groups = crate::groups::get_user_groups(username)?;
    let account_expired = 
        if account.usri4_acct_expires == 0xFFFFFFFF { 
            "Never".to_owned() 
        } else { 
            crate::timestamp_to_datetime(account.usri4_acct_expires as i64)
        };

    let password_last_set = crate::timestamp_to_datetime(
        crate::get_current_timestamp() - account.usri4_password_age as i64
    );

    let last_logon = if account.usri4_last_logon == 0 {
        "Never".to_owned()
    } else {
        crate::timestamp_to_datetime(account.usri4_last_logon as i64)
    };

    let last_logoff = if account.usri4_last_logoff == 0 {
        "Never".to_owned()
    } else {
        crate::timestamp_to_datetime(account.usri4_last_logon as i64)
    };

    println!(        
        "User name                    {}\n\
        Full name                    {}\n\
        User SID                     {}\n\
        Comment                      {}\n\
        User's comment               {}\n\
        Flags                        {}\n\
        Auth flags                   {}\n\
        Country/region code          {}\n\n\
        Account active               {}\n\
        Account expires              {}\n\
        Password expires             {}\n\
        Password last set            {}\n\n\
        Workstations allowed         {}\n\
        Logon script                 {}\n\
        User profile                 {}\n\
        Home directory               {}\n\
        Home directory drive         {}\n\
        Last logon                   {}\n\
        Last logoff                  {}\n\n\
        Local group memberships      {:?}\n\
        Global group memberships     {:?}\n",
        decode_wide_nul_to_string(account.usri4_name).unwrap(),
        decode_wide_nul_to_string(account.usri4_full_name).unwrap(),
        sid_to_string_sid(account.usri4_user_sid).unwrap(),
        decode_wide_nul_to_string(account.usri4_comment).unwrap(),
        decode_wide_nul_to_string(account.usri4_usr_comment).unwrap(),
        account.usri4_flags,
        account.usri4_auth_flags,
        account.usri4_country_code,
        account.usri4_flags != UF_ACCOUNTDISABLE,
        account_expired,
        if account.usri4_password_expired == 0 { "Never" } else { "Password has expired" },
        password_last_set,
        decode_wide_nul_to_string(account.usri4_workstations).unwrap(),
        decode_wide_nul_to_string(account.usri4_script_path).unwrap(),
        decode_wide_nul_to_string(account.usri4_profile).unwrap(),
        decode_wide_nul_to_string(account.usri4_home_dir).unwrap(),
        decode_wide_nul_to_string(account.usri4_home_dir_drive).unwrap(),
        last_logon,
        last_logoff,
        groups.0,
        groups.1,
    );

    Ok(())
}

/// Get user account SID in binary format.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::{
///     get_user_sid,
///     sid_to_string_sid,
/// };
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let mut sid = match get_user_sid(username) {
///         Ok(sid) => sid,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///     
///     let ptr_sid = sid.as_mut_ptr() as *mut std::ffi::c_void;
///     let sid_string = sid_to_string_sid(ptr_sid).unwrap();
///     println!("SID: {}", sid_string);
///}
/// ```
pub fn get_user_sid(username: &str) -> Result<Vec<u8>, u32> {
    let mut pe_use: i32 = 0;
    let mut sid_len: u32 = MAX_NAME;
    let mut domain_len: u32 = MAX_NAME;
    let mut domain_buf: Vec<u16> = vec![0; MAX_NAME as usize];
    let mut sid_buf: Vec<u8> = vec![0; MAX_NAME as usize];
    let wide_username_nul = crate::encode_string_to_wide(username);
    let sid = sid_buf.as_mut_ptr() as *mut core::ffi::c_void;
    unsafe {
        if LookupAccountNameW(
            core::ptr::null_mut(),      // local server
            wide_username_nul.as_ptr(), // account name
            sid,                        // sid
            &mut sid_len,               // sid size
            domain_buf.as_mut_ptr(),    // domain
            &mut domain_len,            // domain size
            &mut pe_use,
        ) == 0
        {
            return Err(GetLastError());
        }
    }

    Ok(sid_buf)
}

/// Checks if provided SID is valid or not
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::{
///     get_user_sid,
///     is_valid_sid
/// };
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let mut sid = match get_user_sid(username) {
///         Ok(sid) => sid,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///
///     let ptr_sid = sid.as_mut_ptr() as *mut std::ffi::c_void;
///     println!("SID valid: {}", is_valid_sid(ptr_sid));
///}
/// ```
pub fn is_valid_sid(sid: *mut std::ffi::c_void) -> bool {
    unsafe {
        if IsValidSid(sid) == 0 {
            return false;
        }
    }

    true
}

/// Converts a string-format SID into a valid, functional SID.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::{
///     get_user_sid,
///     sid_to_string_sid,
///     string_sid_to_sid
/// };
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let mut sid = match get_user_sid(username) {
///         Ok(sid) => sid,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///     
///     let ptr_sid = sid.as_mut_ptr() as *mut std::ffi::c_void;
///     let sid_string = sid_to_string_sid(ptr_sid).unwrap();
///     let sid_from_sid_string = string_sid_to_sid(sid_string).unwrap();
///     println!("Raw SID: {:?}", sid_from_sid_string);
///}
/// ```
pub fn string_sid_to_sid(string_sid: String) -> Result<Vec<u8>, u32> {
    let sid_wide_string = crate::encode_string_to_wide(&string_sid);
    let mut sid = std::ptr::null_mut();

    let sid_buf = unsafe {
        if ConvertStringSidToSidW(
            sid_wide_string.as_ptr(),
            &mut sid as *mut *mut std::ffi::c_void,
        ) == 0
        {
            return Err(GetLastError());
        }

        std::slice::from_raw_parts(sid as *mut u8, MAX_NAME as usize)
    };

    Ok(sid_buf.to_vec())
}

/// Converts SID into a string-format SID.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::{
///     get_user_sid,
///     sid_to_string_sid,
/// };
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let mut sid = match get_user_sid(username) {
///         Ok(sid) => sid,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///     
///     let ptr_sid = sid.as_mut_ptr() as *mut std::ffi::c_void;
///     let sid_string = sid_to_string_sid(ptr_sid).unwrap();
///     println!("String SID: {}", sid_string);
///}
/// ```
pub fn sid_to_string_sid(sid: *mut std::ffi::c_void) -> Result<String, u32> {
    unsafe {
        if !is_valid_sid(sid) {
            return Err(GetLastError());
        }

        let mut string_sid = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut string_sid) == 0 {
            return Err(GetLastError());
        }

        Ok(crate::decode_wide_nul_to_string(string_sid).unwrap())
    }
}

/// Returns of length of valid SID.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::{
///     get_user_sid,
///     get_sid_length
/// };
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let mut sid = match get_user_sid(username) {
///         Ok(sid) => sid,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///
///     let ptr_sid = sid.as_mut_ptr() as *mut std::ffi::c_void;
///     let sid_len = get_sid_length(&mut sid).unwrap();
///     println!("SID length: {}", sid_len);
///}
/// ```
pub fn get_sid_length(sid: &mut Vec<u8>) -> Result<u32, u32> {
    let ptr_sid = sid.as_mut_ptr() as *mut std::ffi::c_void;
    if !is_valid_sid(ptr_sid) {
        return Err(unsafe { GetLastError() });
    }

    Ok(unsafe { GetLengthSid(ptr_sid) })
}

/// Get user account by specified SID.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::users::{
///     get_user_sid,
///     get_user_by_sid
/// };
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let mut sid = match get_user_sid(username) {
///         Ok(sid) => sid,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///
///     let ptr_sid = sid.as_mut_ptr() as *mut std::ffi::c_void;
///     let username_from_sid = get_user_by_sid(ptr_sid).unwrap();
///     println!("Username resolved from SID: {}", username_from_sid);
///}
/// ```
pub fn get_user_by_sid(sid: *mut std::ffi::c_void) -> Result<String, u32> {
    let mut pe_use: i32 = 0;
    let mut domain_buf: [u16; MAX_NAME as usize] = [0; MAX_NAME as usize];
    let mut username: [u16; MAX_NAME as usize] = [0; MAX_NAME as usize];
    let mut dw_size = MAX_NAME;

    unsafe {
        if LookupAccountSidW(
            std::ptr::null_mut(),    // local server
            sid,                     // account name
            username.as_mut_ptr(),   // sid
            &mut dw_size,            // sid size
            domain_buf.as_mut_ptr(), // domain
            &mut dw_size,            // domain size
            &mut pe_use,
        ) == 0
        {
            return Err(GetLastError());
        }
    }

    Ok(String::from_utf16_lossy(&username))
}
