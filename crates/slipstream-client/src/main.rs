fn main() {
    // Use the library entrypoint to run the CLI path; preserve exit code semantics.
    let args: Vec<String> = std::env::args().collect();
    let code = slipstream_client::run_with_args(args);
    std::process::exit(code);
}