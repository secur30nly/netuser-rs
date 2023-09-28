use crate::decode_wide_nul_to_string;
use crate::users::sid_to_string_sid;
use std::ptr::null_mut;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetLocalGroupAddMembers, NetLocalGroupDelMembers,
    NetLocalGroupGetMembers, NetUserGetGroups, NetUserGetLocalGroups, GROUP_USERS_INFO_0,
    LG_INCLUDE_INDIRECT, LOCALGROUP_MEMBERS_INFO_0, LOCALGROUP_MEMBERS_INFO_2,
    LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH,
};

/// Add user to specified local group.
/// If `deletion` param is `true` - delete specified user account from local group.
///
/// If failed - returns Windows error.
///
/// This is a private function and should not be used directly.
/// Use `add_local_user_to_group` and `del_local_user_from_group` instead.
unsafe fn manage_group_users(username: &str, groupname: &str, deletion: bool) -> Result<(), u32> {
    let wide_groupname_nul = crate::encode_string_to_wide(groupname);
    let sid = crate::users::get_user_sid(username)?;
    let mut group_info = core::mem::zeroed::<LOCALGROUP_MEMBERS_INFO_0>();

    group_info.lgrmi0_sid = sid.as_ptr() as *mut core::ffi::c_void;

    let rc: u32;
    if deletion {
        rc = NetLocalGroupDelMembers(
            null_mut(),
            wide_groupname_nul.as_ptr(),
            0,
            &group_info as *const _ as *const u8,
            1,
        );
    } else {
        rc = NetLocalGroupAddMembers(
            null_mut(),
            wide_groupname_nul.as_ptr(),
            0,
            &group_info as *const _ as *const u8,
            1,
        );
    }

    if rc != NERR_Success {
        return Err(rc);
    }

    Ok(())
}

/// Get members of local group. If sids_only is `true` - returs members SIDs instead names.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::groups::get_group_members;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let groupname = "Remote Desktop Users";
///     let sids_only = false;  // get usernames of group members instead of SIDs
///     let group_members = match get_group_members(groupname, sids_only) {
///         Ok(members) => members,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///
///     for member in group_members {
///         println!("\"{}\" member name: {}", groupname, member);
///     }
/// }
/// ```
pub fn get_group_members(groupname: &str, sids_only: bool) -> Result<Vec<String>, u32> {
    let wide_groupname_nul = crate::encode_string_to_wide(groupname);
    let mut buffer = null_mut();
    let mut entries_read = 0;
    let mut total_entries = 0;

    let group_members_slice = unsafe {
        let rc = NetLocalGroupGetMembers(
            null_mut(),
            wide_groupname_nul.as_ptr(),
            2, // get sids, account names and domain instead sids only (level 0)
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            null_mut(),
        );
        if rc != NERR_Success {
            return Err(rc);
        }

        std::slice::from_raw_parts(
            buffer as *const u8 as *const LOCALGROUP_MEMBERS_INFO_2,
            entries_read as usize,
        )
    };

    let mut group_members = Vec::<String>::with_capacity(group_members_slice.len());
    if sids_only {
        for member in group_members_slice {
            group_members.push(sid_to_string_sid(member.lgrmi2_sid)?);
        }
    } else {
        for member in group_members_slice {
            group_members
                .push(decode_wide_nul_to_string(member.lgrmi2_domainandname).unwrap());
        }
    }

    Ok(group_members)
}

/// List all user groups - local and global. `0` element of tuple - local groups, `1` - global groups
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::groups::get_user_groups;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let user_groups = match get_user_groups(username) {
///         Ok(groups) => groups,
///         Err(err) => {
///             log::error!("Error: {} - {}\n", err, win_err_text(err));
///             return;
///         }
///     };
///     for local_group in user_groups.0 {
///         println!("  {}", local_group);
///     }
///
///     for global_group in user_groups.1 {
///         println!("  {}", global_group);
///     }
///}
/// ```
pub fn get_user_groups(username: &str) -> Result<(Vec<String>, Vec<String>), u32> {
    let wide_username_nul = crate::encode_string_to_wide(username);
    let mut buffer = null_mut();
    let mut entries_read = 0;
    let mut total_entries = 0;
    let mut rc;

    let local_groups_slice = unsafe {
        rc = NetUserGetLocalGroups(
            null_mut(),
            wide_username_nul.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT, // the function also returns the names of the local groups in which the user is indirectly a member
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
        );
        if rc != NERR_Success {
            return Err(rc);
        }

        std::slice::from_raw_parts(
            buffer as *const u8 as *const LOCALGROUP_USERS_INFO_0,
            entries_read as usize,
        )
    };

    let mut local_groups = Vec::<String>::with_capacity(local_groups_slice.len());
    for group in local_groups_slice {
        local_groups.push(decode_wide_nul_to_string(group.lgrui0_name).unwrap());
    }

    buffer = null_mut();
    entries_read = 0;
    total_entries = 0;

    let global_groups_slice = unsafe {
        rc = NetUserGetGroups(
            null_mut(),
            wide_username_nul.as_ptr(),
            0,
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
        );
        if rc != NERR_Success {
            return Err(rc);
        }

        std::slice::from_raw_parts(
            buffer as *const u8 as *const GROUP_USERS_INFO_0,
            entries_read as usize,
        )
    };

    let mut global_groups = Vec::<String>::with_capacity(global_groups_slice.len());

    for group in global_groups_slice {
        global_groups.push(decode_wide_nul_to_string(group.grui0_name).unwrap());
    }

    Ok((local_groups, global_groups))
}

/// Delete local user account from specified local group.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::groups::delete_user_from_group;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let groupname = "Administrators";
///     if let Err(err) = delete_user_from_group(username, groupname) {
///         log::error!("Error: {} - {}\n", err, win_err_text(err));
///         return;
///     }
///}
/// ```
pub fn delete_user_from_group(username: &str, groupname: &str) -> Result<(), u32> {
    unsafe { manage_group_users(username, groupname, true) }
}

/// Add local user account to specified local group.
///
/// If failed - returns Windows error.
///
/// # Examples
///
/// ```no_run
/// use netuser_rs::groups::add_user_to_group;
/// use netuser_rs::win_err_text;
///
/// fn main() {
///     let username = "pentester";
///     let groupname = "Administrators";
///     if let Err(err) = add_user_to_group(username, groupname) {
///         log::error!("Error: {} - {}\n", err, win_err_text(err));
///         return;
///     }
///}
/// ```
pub fn add_user_to_group(username: &str, groupname: &str) -> Result<(), u32> {
    unsafe { manage_group_users(username, groupname, false) }
}
