// crates/slipstream-client/src/main.rs
// Thin CLI shim that calls into the library entrypoint so both CLI and cdylib share logic.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = run_with_args(args);
    std::process::exit(code);
}