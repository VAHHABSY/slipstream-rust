// crates/slipstream-client/src/lib.rs
//! library entrypoint for slipstream-client.
//! the original cli main logic is refactored into `run_with_args` so we can build a cdylib.
//! exposes minimal extern "c" wrappers (`slipstream_start` / `slipstream_stop`) for android.

mod dns;
mod error;
mod pacing;
mod pinning;
mod runtime;
mod streams;

use clap::{parser::valuesource, arggroup, commandfactory, fromargmatches, parser};
use slipstream_core::{
    normalize_domain, parse_host_port, parse_host_port_parts, sip003, addresskind, hostport,
};
use slipstream_ffi::{clientconfig, resolvermode, resolverspec};
use tokio::runtime::builder;
use tracing_subscriber::envfilter;

use runtime::run_client;

#[derive(parser, debug)]
#[command(
    name = "slipstream-client",
    about = "slipstream-client - a high-performance covert channel over dns (client)",
    group(
        arggroup::new("resolvers")
            .multiple(true)
            .args(["resolver", "authoritative"])
    )
)]
pub struct args {
    #[arg(long = "tcp-listen-host", default_value = "::")]
    tcp_listen_host: string,
    #[arg(long = "tcp-listen-port", short = 'l', default_value_t = 5201)]
    tcp_listen_port: u16,
    #[arg(long = "resolver", short = 'r', value_parser = parse_resolver)]
    resolver: vec<hostport>,
    #[arg(
        long = "congestion-control",
        short = 'c',
        value_parser = ["bbr", "dcubic"]
    )]
    congestion_control: option<string>,
    #[arg(long = "authoritative", value_parser = parse_resolver)]
    authoritative: vec<hostport>,
    #[arg(
        short = 'g',
        long = "gso",
        num_args = 0..=1,
        default_value_t = false,
        default_missing_value = "true"
    )]
    gso: bool,
    #[arg(long = "domain", short = 'd', value_parser = parse_domain)]
    domain: option<string>,
    #[arg(long = "cert", value_name = "path")]
    cert: option<string>,
    #[arg(long = "keep-alive-interval", short = 't', default_value_t = 400)]
    keep_alive_interval: u16,
    #[arg(long = "debug-poll")]
    debug_poll: bool,
    #[arg(long = "debug-streams")]
    debug_streams: bool,
}

/// run the main client logic and return an exit code.
/// accepts concrete vec<string> to satisfy clap trait bounds.
pub fn run_with_args(args: vec<string>) -> i32 {
    init_logging();

    // parse args with clap
    let matches = match args::command().try_get_matches_from(args.clone()) {
        ok(m) => m,
        err(err) => {
            // let clap print its message and exit as before
            err.exit();
        }
    };
    let args = match args::from_arg_matches(&matches) {
        ok(a) => a,
        err(err) => {
            err.exit();
        }
    };

    let sip003_env = match sip003::read_sip003_env() {
        ok(e) => e,
        err(err) => {
            tracing::error!("sip003 env error: {}", err);
            return 2;
        }
    };

    if sip003_env.is_present() {
        tracing::info!("sip003 env detected; applying ss_* overrides with cli precedence");
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
        "ss_local",
    ) {
        ok(hp) => hp,
        err(err) => {
            tracing::error!("sip003 env error: {}", err);
            return 2;
        }
    };

    let domain = if let some(domain) = args.domain.clone() {
        domain
    } else {
        let option_domain = match parse_domain_option(&sip003_env.plugin_options) {
            ok(opt) => opt,
            err(err) => {
                tracing::error!("sip003 env error: {}", err);
                return 2;
            }
        };
        if let some(domain) = option_domain {
            domain
        } else {
            tracing::error!("a domain is required");
            return 2;
        }
    };

    let cli_has_resolvers = has_cli_resolvers(&matches);
    let resolvers = if cli_has_resolvers {
        match build_resolvers(&matches, true) {
            ok(r) => r,
            err(err) => {
                tracing::error!("resolver error: {}", err);
                return 2;
            }
        }
    } else {
        let resolver_options = match parse_resolvers_from_options(&sip003_env.plugin_options) {
            ok(o) => o,
            err(err) => {
                tracing::error!("sip003 env error: {}", err);
                return 2;
            }
        };
        if !resolver_options.resolvers.is_empty() {
            resolver_options.resolvers
        } else {
            let sip003_remote = match sip003::parse_endpoint(
                sip003_env.remote_host.as_deref(),
                sip003_env.remote_port.as_deref(),
                "ss_remote",
            ) {
                ok(r) => r,
                err(err) => {
                    tracing::error!("sip003 env error: {}", err);
                    return 2;
                }
            };
            if let some(endpoint) = &sip003_check_opt(&sip003_remote) {
                let mode = if resolver_options.authoritative_remote {
                    resolvermode::authoritative
                } else {
                    resolvermode::recursive
                };
                let resolver =
                    match parse_host_port_parts(&endpoint.host, endpoint.port, addresskind::resolver)
                    {
                        ok(r) => r,
                        err(err) => {
                            tracing::error!("sip003 env error: {}", err);
                            return 2;
                        }
                    };
                vec![resolverspec { resolver, mode }]
            } else {
                tracing::error!("at least one resolver is required");
                return 2;
            }
        }
    };

    let congestion_control = if args.congestion_control.is_some() {
        args.congestion_control.clone()
    } else {
        match parse_congestion_control(&sip003_env.plugin_options) {
            ok(opt) => opt,
            err(err) => {
                tracing::error!("sip003 env error: {}", err);
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
        tracing::warn!(
            "server certificate pinning is disabled; this allows mitm. provide --cert to pin the server leaf, or dismiss this if your underlying tunnel provides authentication."
        );
    }

    let keep_alive_interval = if cli_provided(&matches, "keep_alive_interval") {
        args.keep_alive_interval
    } else {
        match parse_keep_alive_interval(&sip003_env.plugin_options) {
            ok(opt) => opt.unwrap_or(args.keep_alive_interval),
            err(err) => {
                tracing::error!("sip003 env error: {}", err);
                return 2;
            }
        }
    };

    let config = clientconfig {
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

    let runtime = match builder::new_current_thread().enable_io().enable_time().build() {
        ok(r) => r,
        err(err) => {
            tracing::error!("failed to build tokio runtime: {}", err);
            return 1;
        }
    };

    match runtime.block_on(run_client(&config)) {
        ok(code) => code,
        err(err) => {
            tracing::error!("client error: {}", err);
            1
        }
    }
}

// helper: unwrap option<&t> to option<&t> (preserve previous logic naming)
fn sip003_check_opt<t>(opt: &option<t>) -> option<&t> {
    opt.as_ref()
}

// ----------------- helpers -----------------

fn init_logging() {
    let filter = envfilter::try_from_default_env().unwrap_or_else(|_| envfilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}

fn parse_domain(input: &str) -> result<string, string> {
    normalize_domain(input).map_err(|err| err.to_string())
}

fn parse_resolver(input: &str) -> result<hostport, string> {
    parse_host_port(input, 53, addresskind::resolver).map_err(|err| err.to_string())
}

fn build_resolvers(matches: &clap::argmatches, require: bool) -> result<vec<resolverspec>, string> {
    let mut ordered = vec::new();
    collect_resolvers(matches, "resolver", resolvermode::recursive, &mut ordered)?;
    collect_resolvers(
        matches,
        "authoritative",
        resolvermode::authoritative,
        &mut ordered,
    )?;
    if ordered.is_empty() && require {
        return err("at least one resolver is required".to_string());
    }
    ordered.sort_by_key(|(idx, _)| *idx);
    ok(ordered.into_iter().map(|(_, spec)| spec).collect())
}

fn collect_resolvers(
    matches: &clap::argmatches,
    name: &str,
    mode: resolvermode,
    ordered: &mut vec<(usize, resolverspec)>,
) -> result<(), string> {
    let indices: vec<usize> = matches.indices_of(name).into_iter().flatten().collect();
    let values: vec<hostport> = matches
        .get_many::<hostport>(name)
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    if indices.len() != values.len() {
        return err(format!("mismatched {} arguments", name));
    }
    for (idx, resolver) in indices.into_iter().zip(values) {
        ordered.push((idx, resolverspec { resolver, mode }));
    }
    ok(())
}

fn cli_provided(matches: &clap::argmatches, id: &str) -> bool {
    matches.value_source(id) == some(valuesource::commandline)
}

fn has_cli_resolvers(matches: &clap::argmatches) -> bool {
    matches
        .get_many::<hostport>("resolver")
        .map(|values| values.len() > 0)
        .unwrap_or(false)
        || matches
            .get_many::<hostport>("authoritative")
            .map(|values| values.len() > 0)
            .unwrap_or(false)
}

fn parse_domain_option(options: &[sip003::sip003option]) -> result<option<string>, string> {
    let mut domain = none;
    let mut saw_domain = false;
    for option in options {
        if option.key == "domain" {
            if saw_domain {
                return err("sip003 domain option must not be repeated".to_string());
            }
            saw_domain = true;
            let mut entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
            if entries.len() > 1 {
                return err("sip003 domain option must contain a single value".to_string());
            }
            let entry = entries
                .pop()
                .ok_or_else(|| "sip003 domain option must contain a single value".to_string())?;
            let normalized = normalize_domain(&entry).map_err(|err| err.to_string())?;
            domain = some(normalized);
        }
    }
    ok(domain)
}

struct resolveroptions {
    resolvers: vec<resolverspec>,
    authoritative_remote: bool,
}

fn parse_resolvers_from_options(
    options: &[sip003::sip003option],
) -> result<resolveroptions, string> {
    let mut ordered = vec::new();
    let mut authoritative_remote = false;
    for option in options {
        let mode = match option.key.as_str() {
            "resolver" => resolvermode::recursive,
            "authoritative" => resolvermode::authoritative,
            _ => continue,
        };
        let trimmed = option.value.trim();
        if trimmed.is_empty() {
            if mode == resolvermode::authoritative {
                authoritative_remote = true;
                continue;
            }
            return err("empty resolver value is not allowed".to_string());
        }
        let entries = sip003::split_list(&option.value).map_err(|err| err.to_string())?;
        for entry in entries {
            let resolver = parse_host_port(&entry, 53, addresskind::resolver)
                .map_err(|err| err.to_string())?;
            ordered.push(resolverspec { resolver, mode });
        }
    }
    ok(resolveroptions {
        resolvers: ordered,
        authoritative_remote,
    })
}

fn parse_congestion_control(options: &[sip003::sip003option]) -> result<option<string>, string> {
    let mut last = none;
    for option in options {
        if option.key == "congestion-control" {
            let value = option.value.trim();
            if value != "bbr" && value != "dcubic" {
                return err(format!("invalid congestion-control value: {}", value));
            }
            last = some(value.to_string());
        }
    }
    ok(last)
}

fn parse_keep_alive_interval(options: &[sip003::sip003option]) -> result<option<u16>, string> {
    let mut last = none;
    for option in options {
        if option.key == "keep-alive-interval" {
            let value = option.value.trim();
            let parsed = value
                .parse::<u16>()
                .map_err(|_| format!("invalid keep-alive-interval value: {}", value))?;
            last = some(parsed);
        }
    }
    ok(last)
}

// ----------------- minimal cdylib-friendly externs -----------------

use std::sync::atomic::{atomicbool, ordering};
use std::thread;

static started: atomicbool = atomicbool::new(false);

/// start slipstream in a background thread using the current process args.
/// returns 0 if background thread was spawned, non-zero for immediate error.
#[no_mangle]
pub extern "c" fn slipstream_start() -> i32 {
    if started.swap(true, ordering::seqcst) {
        // already started
        return 0;
    }

    // capture current process args
    let args: vec<string> = std::env::args().collect();
    thread::spawn(|| {
        let code = run_with_args(args);
        if code != 0 {
            eprintln!("slipstream exited with code {}", code);
        }
    });

    0
}

/// stop slipstream (best-effort); you must implement an actual stop/shutdown mechanism
/// in your runtime for a graceful shutdown (not provided here).
#[no_mangle]
pub extern "c" fn slipstream_stop() {
    started.store(false, ordering::seqcst);
}

/// compatibility wrapper: export slipstream_main symbol expected by the android loader.
/// non-blocking: delegates to `slipstream_start()` which spawns the runtime thread.
#[no_mangle]
pub extern "c" fn slipstream_main() -> i32 {
    slipstream_start()
}

/// some loaders look for `main`. export a thin wrapper so loaders that expect `main` succeed.
/// this is an exported symbol inside the library only; it doesn't conflict with your binary `main`.
#[no_mangle]
pub extern "c" fn main() -> i32 {
    slipstream_start()
}