use std::env;

fn main() -> anyhow::Result<()> {
    match env::args().nth(1).as_deref() {
        Some("build-all") => build_all(),
        Some("test-all") => test_all(),
        Some("release") => release(),
        _ => {
            eprintln!("usage: cargo xtask <task>");
            eprintln!("tasks: build-all, test-all, release");
            Ok(())
        }
    }
}

fn build_all() -> anyhow::Result<()> {
    Ok(())
}

fn test_all() -> anyhow::Result<()> {
    Ok(())
}

fn release() -> anyhow::Result<()> {
    Ok(())
}
