use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create local user account
    AddUser {
        /// Name of the new local user account
        #[arg(short, long)]
        username: String,
        /// Password of the new local user account
        #[arg(short, long)]
        password: String,
        /// Description of the new local user account (Optional)
        #[arg(short, long)]
        description: Option<String>,

    },
    /// Add new privilege to user account
    AddPriv {
        /// Account name to add privilege
        #[arg(short, long)]
        username: String,
        /// Name of the privilege to add to the account
        #[arg(long = "priv")]
        privilege: String,
    },
    /// Add local user account to local group
    AddToGroup {
        /// Name of the account to add to the local group
        #[arg(short, long)]
        username: String,
        /// Name of the local group where to add the account
        #[arg(short, long)]
        groupname: String,
    },
    /// Delete local user account
    DelUser {
        /// Name of the local user account to delete
        #[arg(short, long)]
        username: String,
    },
    /// Delete user account privilege
    DelPriv {
        /// Account name to delete privilege
        #[arg(short, long)]
        username: String,
        /// Name of the privilege to delete from the account
        #[arg(long = "priv")]
        privilege: String,
    },
    /// Delete local user account from local group
    DelFromGroup {
        /// Name of the account to delete from the local group
        #[arg(short, long)]
        username: String,
        /// Name of the local group where to delete the account
        #[arg(short, long)]
        groupname: String,
    },
    /// Change local user account password with new one
    ChangePass {
        /// Name of the account to change current password
        #[arg(short, long)]
        username: String,
        /// New password of the local user account
        #[arg(short, long)]
        password: String,
    },
    /// Enable local user account
    EnableUser {
        /// Name of the account to enable
        #[arg(short, long)]
        username: String,
    },
    /// Disable local user account
    DisableUser {
        /// Name of the account to disable
        #[arg(short, long)]
        username: String,
    },
    /// List all user accounts
    GetUsers {},
    /// Get detailed info about user account
    GetUser {
        /// Name of the user account to show detailed information
        #[arg(short, long)]
        username: String
    },
    /// Get all users that have specified privilege
    GetUsersByPriv {
        /// Name of the privilege for user search
        #[arg(long = "priv")]
        privilege: String,
    },
    /// List all user groups
    GetUserGroups {
        /// Name of the local user account to show all groups
        #[arg(short, long)]
        username: String,
    },
    /// List all group members
    GetGroupMembers {
        /// Name of the local group to show all members
        #[arg(short, long)]
        groupname: String,

        /// List SIDs of group members instead of names (Optional)
        #[arg(long)]
        sids_only: bool,
    },
    /// List privileges of local user account or local group
    GetPrivs {
        /// Name of the local user account or group to show all privileges
        #[arg(short, long)]
        name: String,
    },
}
