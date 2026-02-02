// crates/slipstream-client/src/lib.rs
//! Library entrypoint for slipstream-client.
//! The original CLI main logic is refactored into `run_with_args` so we can build a cdylib.
//! Exposes minimal extern "C" wrappers (`slipstream_start` / `slipstream_stop`) for Android.

mod dns;
mod error;
mod pacing;
mod pinning;
mod runtime;
mod streams;

use clap::{parser::ValueSource, ArgGroup, CommandFactory, FromArgMatches, Parser};
use slipstream_core::{
    normalize_domain, parse_host_port, parse_host_port_parts, sip003, AddressKind, HostPort,
};
use slipstream_ffi::{ClientConfig, ResolverMode, ResolverSpec};
use tokio::runtime::Builder;
use tracing_subscriber::EnvFilter;

use runtime::run_client;

#[derive(Parser, Debug)]
#[command(
    name = "slipstream-client",
    about = "slipstream-client - A high-performance covert channel over DNS (client)",
    group(
        ArgGroup::new("resolvers")
            .multiple(true)
            .args(["resolver", "authoritative"])
    )
)]
pub struct Args {
    #[arg(long = "tcp-listen-host", default_value = "::")]
    tcp_listen_host: String,
    #[arg(long = "tcp-listen-port", short = 'l', default_value_t = 5201)]
    tcp_listen_port: u16,
    #[arg(long = "resolver", short = 'r', value_parser = parse_resolver)]
    resolver: Vec<HostPort>,
    #[arg(
        long = "congestion-control",
        short = 'c',
        value_parser = ["bbr", "dcubic"]
    )]
    congestion_control: Option<String>,
    #[arg(long = "authoritative", value_parser = parse_resolver)]
    authoritative: Vec<HostPort>,
    #[arg(
        short = 'g',
        long = "gso",
        num_args = 0..=1,
        default_value_t = false,
        default_missing_value = "true"
    )]
    gso: bool,
    #[arg(long = "domain", short = 'd', value_parser = parse_domain)]
    domain: Option<String>,
    #[arg(long = "cert", value_name = "PATH")]
    cert: Option<String>,
    #[arg(long = "keep-alive-interval", short = 't', default_value_t = 400)]
    keep_alive_interval: u16,
    #[arg(long = "debug-poll")]
    debug_poll: bool,
    #[arg(long = "debug-streams")]
    debug_streams: bool,
}

/// Run the main client logic and return an exit code.
/// Accepts concrete Vec<String> to satisfy clap trait bounds.
pub fn run_with_args(args: Vec<String>) -> i32 {
    // Initialize logging (Android logger + tracing subscriber)
    init_logging();

    log::info!("run_with_args called; args={:?}", args);

    // Parse args with clap
    let matches = match Args::command().try_get_matches_from(args.clone()) {
        Ok(m) => m,
        Err(err) => {
            // let clap print its message and exit as before
            err.exit();
        }
    };
    let args = match Args::from_arg_matches(&matches) {
        Ok(a) => a,
        Err(err) => {
            err.exit();
        }
    };

    let sip003_env = match sip003::read_sip003_env() {
        Ok(e) => e,
        Err(err) => {
            log::error!("SIP003 env error: {}", err);
            eprintln!("SIP003 env error: {}", err);
            return 2;
        }
    };

    if sip003_env.is_present() {
        log::info!("SIP003 env detected; applying SS_* overrides with CLI precedence");
    }

    let tcp_listen_host_provided = cli_provided(&matches, "tcp_listen_host");
    let tcp_listen_port_provided = cli_provided(&matches, "tcp_listen_port");
    let (tcp_listen_host, tcp_listen_port) = match sip003::select_host_port(
        &args.tcp_listen_host,
        args.tcp_listen_port,
        tcp_listen_host_provided,
        tcp_listen_port_provided,
        sip003_env.local_host.as_deref(),
        sip003_env.local_port.as_deref(),
        "SS_LOCAL",
    ) {
        Ok(hp) => hp,
        Err(err) => {
            log::error!("SIP003 select_host_port error: {}", err);
            eprintln!("SIP003 select_host_port error: {}", err);
            return 2;
        }
    };

    let domain = if let Some(domain) = args.domain.clone() {
        domain
    } else {
        let option_domain = match parse_domain_option(&sip003_env.plugin_options) {
            Ok(opt) => opt,
            Err(err) => {
                log::error!("SIP003 env error: {}", err);
                eprintln!("SIP003 env error: {}", err);
                return 2;
            }
        };
        if let Some(domain) = option_domain {
            domain
        } else {
            log::error!("A domain is required");
            eprintln!("A domain is required");
            return 2;
        }
    };

    let cli_has_resolvers = has_cli_resolvers(&matches);
    let resolvers = if cli_has_resolvers {
        match build_resolvers(&matches, true) {
            Ok(r) => r,
            Err(err) => {
                log::error!("Resolver error: {}", err);
                eprintln!("Resolver error: {}", err);
                return 2;
            }
        }
    } else {
        let resolver_options = match parse_resolvers_from_options(&sip003_env.plugin_options) {
            Ok(o) => o,
            Err(err) => {
                log::error!("SIP003 env error: {}", err);
                eprintln!("SIP003 env error: {}", err);
                return 2;
            }
        };
        if !resolver_options.resolvers.is_empty() {
            resolver_options.resolvers
        } else {
            let sip003_remote = match sip003::parse_endpoint(
                sip003_env.remote_host.as_deref(),
                sip003_env.remote_port.as_deref(),
                "SS_REMOTE",
            ) {
                Ok(r) => r,
                Err(err) => {
                    log::error!("SIP003 env error: {}", err);
                    eprintln!("SIP003 env error: {}", err);
                    return 2;
                }
            };
            if let Some(endpoint) = &sip003_check_opt(&sip003_remote) {
                let mode = if resolver_options.authoritative_remote {
                    ResolverMode::Authoritative
                } else {
                    ResolverMode::Recursive
                };
                let resolver =
                    match parse_host_port_parts(&endpoint.host, endpoint.port, AddressKind::Resolver)
                    {
                        Ok(r) => r,
                        Err(err) => {
                            log::error!("SIP003 env error: {}", err);
                            eprintln!("SIP003 env error: {}", err);
                            return 2;
                        }
                    };
                vec![ResolverSpec { resolver, mode }]
            } else {
                log::error!("At least one resolver is required");
                eprintln!("At least one resolver is required");
                return 2;
            }
        }
    };

    let congestion_control = if args.congestion_control.is_some() {
        args.congestion_control.clone()
    } else {
        match parse_congestion_control(&sip003_env.plugin_options) {
            Ok(opt) => opt,
            Err(err) => {
                log::error!("SIP003 env error: {}", err);
                eprintln!("SIP003 env error: {}", err);
                return 2;
            }
        }
    };

    let cert = if args.cert.is_some() {
        args.cert.clone()
    } else {
        sip003::last_option_value(&sip003_env.plugin_options, "cert")
    };
    if cert.is_none() {
        log::warn!(
            "Server certificate pinning is disabled; this allows MITM. Provide --cert to pin the server leaf, or dismiss this if your underlying tunnel provides authentication."
        );
        eprintln!("Server certificate pinning is disabled; consider providing --cert");
    }

    let keep_alive_interval = if cli_provided(&matches, "keep_alive_interval") {
        args.keep_alive_interval
    } else {
        match parse_keep_alive_interval(&sip003_env.plugin_options) {
            Ok(opt) => opt.unwrap_or(args.keep_alive_interval),
            Err(err) => {
                log::error!("SIP003 env error: {}", err);
                eprintln!("SIP003 env error: {}", err);
                return 2;
            }
        }
    };

    let config = ClientConfig {
        tcp_listen_host: &tcp_listen_host,
        tcp_listen_port,
        resolvers: &resolvers,
        congestion_control: congestion_control.as_deref(),
        gso: args.gso,
        domain: &domain,
        cert: cert.as_deref(),
        keep_alive_interval: keep_alive_interval as usize,
        debug_poll: args.debug_poll,
        debug_streams: args.debug_streams,
    };

    log::info!(
        "Starting runtime with config: tcp_listen_host={}, tcp_listen_port={}, domain={}",
        tcp_listen_host,
        tcp_listen_port,
        domain
    );

    let runtime = match Builder::new_current_thread().enable_io().enable_time().build() {
        Ok(r) => r,
        Err(err) => {
            log::error!("Failed to build Tokio runtime: {}", err);
            eprintln!("Failed to build Tokio runtime: {}", err);
            return 1;
        }
    };

    match runtime.block_on(run_client(&config)) {
        Ok(code) => {
            log::info!("run_client returned code {}", code);
            code
        }
        Err(err) => {
            log::error!("Client error: {}", err);
            eprintln!("Client error: {}", err);
            1
        }
    }
}

// Helper: unwrap Option<&T> to Option<&T> (preserve previous logic naming)
fn sip003_check_opt<T>(opt: &Option<T>) -> Option<&T> {
    opt.as_ref()
}

// ----------------- helpers -----------------

/// Initialize logging. On Android this also sets up android_logger so logs appear in logcat.
fn init_logging() {
    // Android-specific logger that forwards `log` records to logcat
    #[cfg(target_os = "android")]
    {
        use android_logger::Config;
        use log::LevelFilter;
        // android_logger uses `with_max_level` to set the maximum level observed
        android_logger::init_once(
            Config::default()
                .with_max_level(LevelFilter::Info)
                .with_tag("slipstream"),
        );
    }

    // tracing subscriber for console/CI builds or when running on host
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}

fn parse_domain(input: &str) -> Result<String, String> {
    normalize_domain(input).map_err(|err| err.to_string())
}

fn parse_resolver(input: &str) -> Result<HostPort, String> {
    parse_host_port(input, 53, AddressKind::Resolver).map_err(|err| err.to_string())
}

fn build_resolvers(matches: &clap::ArgMatches, require: bool) -> Result<Vec<ResolverSpec>, String> {
    let mut ordered = Vec::new();
    collect_resolvers(matches, "resolver", ResolverMode::Recursive, &mut ordered)?;
    collect_resolvers(
        matches,
        "authoritative",
        ResolverMode::Authoritative,
        &mut ordered,
    )?;
    if ordered.is_empty() && require {
        return Err("At least one resolver is required".to_string());
    }
    ordered.sort_by_key(|(idx, _)| *idx);
    Ok(ordered.into_iter().map(|(_, spec)| spec).collect())
}

fn collect_resolvers(
    matches: &clap::ArgMatches,
    name: &str,
    mode: ResolverMode,
    ordered: &mut Vec<(usize, ResolverSpec)>,
) -> Result<(), String> {
    let indices: Vec<usize> = matches.indices_of(name).into_iter().flatten().collect();
    let values: Vec<HostPort> = matches
        .get_many::<HostPort>(name)
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    if indices.len() != values.len() {
        return Err(format!("Mismatched {} arguments", name));
    }
    for (idx, resolver) in indices.into_iter().zip(values) {
        ordered.push((idx, ResolverSpec { resolver, mode }));
    }
    Ok(())
}

fn cli_provided(matches: &clap::ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

fn has_cli_resolvers(matches: &clap::ArgMatches) -> bool {
    matches
        .get_many::<HostPort>("resolver")
        .map(|values| values.len() > 0)
        .unwrap_or(false)
        || matches
            .get_many::<HostPort>("authoritative")
            .map(|values| values.len() > 0)
            .unwrap_or(false)
}

fn parse_domain_option(options: &[sip003::Sip003Option]) -> Result<Option<String>, String> {
    let mut domain = None;
    let mut saw_domain = false;
    for option in options {
        if option.key == "domain" {
            if saw_domain {
                return Err("SIP003 domain option must not be repeated".to_string());
            }
            saw_domain = true;
            let mut entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
            if entries.len() > 1 {
                return Err("SIP003 domain option must contain a single value".to_string());
            }
            let entry = entries
                .pop()
                .ok_or_else(|| "SIP003 domain option must contain a single value".to_string())?;
            let normalized = normalize_domain(&entry).map_err(|err| err.to_string())?;
            domain = Some(normalized);
        }
    }
    Ok(domain)
}

struct ResolverOptions {
    resolvers: Vec<ResolverSpec>,
    authoritative_remote: bool,
}

fn parse_resolvers_from_options(
    options: &[sip003::Sip003Option],
) -> Result<ResolverOptions, String> {
    let mut ordered = Vec::new();
    let mut authoritative_remote = false;
    for option in options {
        let mode = match option.key.as_str() {
            "resolver" => ResolverMode::Recursive,
            "authoritative" => ResolverMode::Authoritative,
            _ => continue,
        };
        let trimmed = option.value.trim();
        if trimmed.is_empty() {
            if mode == ResolverMode::Authoritative {
                authoritative_remote = true;
                continue;
            }
            return Err("Empty resolver value is not allowed".to_string());
        }
        let entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
        for entry in entries {
            let resolver = parse_host_port(&entry, 53, AddressKind::Resolver)
                .map_err(|err| err.to_string())?;
            ordered.push(ResolverSpec { resolver, mode });
        }
    }
    Ok(ResolverOptions {
        resolvers: ordered,
        authoritative_remote,
    })
}

fn parse_congestion_control(options: &[sip003::Sip003Option]) -> Result<Option<String>, String> {
    let mut last = None;
    for option in options {
        if option.key == "congestion-control" {
            let value = option.value.trim();
            if value != "bbr" && value != "dcubic" {
                return Err(format!("Invalid congestion-control value: {}", value));
            }
            last = Some(value.to_string());
        }
    }
    Ok(last)
}

fn parse_keep_alive_interval(options: &[sip003::Sip003Option]) -> Result<Option<u16>, String> {
    let mut last = None;
    for option in options {
        if option.key == "keep-alive-interval" {
            let value = option.value.trim();
            let parsed = value
                .parse::<u16>()
                .map_err(|_| format!("Invalid keep-alive-interval value: {}", value))?;
            last = Some(parsed);
        }
    }
    Ok(last)
}

// ----------------- Minimal cdylib-friendly externs -----------------

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

static STARTED: AtomicBool = AtomicBool::new(false);

/// Start slipstream in a background thread using the current process args.
/// Returns 0 if background thread was spawned, non-zero for immediate error.
#[no_mangle]
pub extern "C" fn slipstream_start() -> i32 {
    // Make sure Android logger is initialized when invoked from JNI
    init_logging();
    eprintln!("slipstream_start called");
    log::info!("slipstream_start called");

    if STARTED.swap(true, Ordering::SeqCst) {
        // already started
        log::info!("slipstream already started");
        return 0;
    }

    // capture current process args
    let args: Vec<String> = std::env::args().collect();
    thread::spawn(|| {
        log::info!("slipstream background thread running; args={:?}", args);
        let code = run_with_args(args);
        if code != 0 {
            eprintln!("slipstream exited with code {}", code);
            log::error!("slipstream exited with code {}", code);
        } else {
            log::info!("slipstream exited with code 0");
        }
    });

    0
}

/// Stop slipstream (best-effort); you must implement an actual stop/shutdown mechanism
/// in your runtime for a graceful shutdown (not provided here).
#[no_mangle]
pub extern "C" fn slipstream_stop() {
    log::info!("slipstream_stop called");
    STARTED.store(false, Ordering::SeqCst);
}

/// Compatibility wrapper: export slipstream_main symbol expected by the Android loader.
/// Non-blocking: delegates to `slipstream_start()` which spawns the runtime thread.
#[no_mangle]
pub extern "C" fn slipstream_main() -> i32 {
    slipstream_start()
}

/// Some loaders look for `main`. Export a thin wrapper so loaders that expect `main` succeed.
#[no_mangle]
pub extern "C" fn main() -> i32 {
    slipstream_start()
}