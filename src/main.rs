use netuser_rs::cli::{Cli, Commands};
use clap::Parser;
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new().init().unwrap();
    let cli = Cli::parse();

    match &cli.command {
        Commands::AddUser { username, password, description } => {
            if let Err(err) = netuser_rs::users::add_user(username, password, description) {
                log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                return;
            }
            log::info!("Account \"{}\" created", username);
        }
        Commands::DelUser { username } => {
            if let Err(err) = netuser_rs::users::delete_user(username.as_str()) {
                log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                return;
            }
            log::info!("Account \"{}\" deleted", username);
        }
        Commands::ChangePass { username, password } => {
            if let Err(err) = netuser_rs::users::change_user_password(username, password) {
                log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                return;
            }
            log::info!("Password of \"{}\" account changed", username);
        }
        Commands::AddToGroup {
            username,
            groupname,
        } => {
            if let Err(err) = netuser_rs::groups::add_user_to_group(username, groupname) {
                log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                return;
            }
            log::info!("The operation completed successfully");
        }
        Commands::DelFromGroup {
            username,
            groupname,
        } => {
            if let Err(err) = netuser_rs::groups::delete_user_from_group(username, groupname) {
                log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                return;
            }
            log::info!("The operation completed successfully");
        }
        Commands::GetUserGroups { username } => {
            let user_groups = match netuser_rs::groups::get_user_groups(username) {
                Ok(groups) => groups,
                Err(err) => {
                    log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                    return;
                }
            };
            log::info!("Local groups of \"{}\": ", username);
            for local_group in user_groups.0 {
                println!("  {}", local_group);
            }

            log::info!("Global groups of \"{}\": ", username);
            for global_group in user_groups.1 {
                println!("  {}", global_group);
            }
        }
        Commands::GetGroupMembers {
            groupname,
            sids_only,
        } => {
            let group_members = match netuser_rs::groups::get_group_members(
                groupname, 
                sids_only.to_owned()
            ) {
                Ok(members) => members,
                Err(err) => {
                    log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                    return;
                }
            };
            log::info!("Members of \"{}\" group: ", groupname);
            for member in group_members {
                println!("  {}", member);
            }
        }
        Commands::AddPriv {
            username,
            privilege,
        } => {
            if let Err(err) = netuser_rs::privs::add_user_privilege(username, privilege) {
                log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                return;
            }
            log::info!(
                "Privilege \"{}\" added to \"{}\" account",
                privilege,
                username
            );
        }
        Commands::DelPriv {
            username,
            privilege,
        } => {
            if let Err(err) = netuser_rs::privs::delete_user_privilege(username, privilege) {
                log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                return;
            }
            log::info!(
                "Privilege \"{}\" removed from \"{}\" account",
                privilege,
                username
            );
        }
        Commands::GetPrivs { name } => {
            let privileges = match netuser_rs::privs::get_user_privileges(name) {
                Ok(privileges) => privileges,
                Err(err) => {
                    log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                    return;
                }
            };
            log::info!("Privileges of \"{}\" account:", name);
            for privilege in privileges {
                println!("  {}", privilege);
            }
        }
        Commands::GetUsers {} => {
            let usernames = match netuser_rs::users::get_users() {
                Ok(usernames) => usernames,
                Err(err) => {
                    log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                    return;
                }
            };
            log::info!("User accounts: ");
            for username in usernames {
                println!("  {}", username);
            }
        }
        Commands::GetUsersByPriv { privilege } => {
            let usernames = match netuser_rs::privs::get_users_by_privilege(privilege) {
                Ok(usernames) => usernames,
                Err(err) => {
                    log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                    return;
                }
            };
            log::info!("User accounts / groups with \"{}\" privilege: ", privilege);
            for username in usernames {
                println!("  {}", username);
            }
        }
        Commands::GetUser { username } => {
            log::info!("Detailed information about \"{}\" user account: ", username);
            if let Err(err) = netuser_rs::users::print_user_detailed(username) {
                log::error!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
                return;
            }
        },
    }
}
