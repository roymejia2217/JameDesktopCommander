//! Non-release probe for a fresh process to obtain the library-checked procfs handle.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _proc_fd = rustix_linux_procfs::proc_self_fd()?;
    println!("VERIFIED_PROC_FD_AVAILABLE_NONRELEASE");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux only: procfs probe unavailable");
    std::process::exit(1);
}
