#[cfg(windows)]
fn main() {
    use tunnel_operator_authority::{compare_registered_tunnel_task_principal, ProcessSidEvidence};
    match compare_registered_tunnel_task_principal() {
        Ok(ProcessSidEvidence::SameAccount) => {
            println!("READ_ONLY_TASK_SID_EQUALITY_NOT_AUTHORIZATION");
        }
        Ok(ProcessSidEvidence::DifferentAccount) => {
            println!("READ_ONLY_TASK_SID_MISMATCH");
        }
        Err(_) => {
            println!("READ_ONLY_TASK_SID_UNVERIFIABLE");
        }
    }
}

#[cfg(not(windows))]
fn main() {
    println!("NOT_WINDOWS");
}
