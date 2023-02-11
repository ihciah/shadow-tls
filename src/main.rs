#![allow(stable_features)]
#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]

mod client;
mod helper_v2;
mod server;
mod sip003;
mod util;

use std::fmt::Display;

use clap::{Parser, Subcommand};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*, EnvFilter};

use crate::{
    client::{parse_client_names, ShadowTlsClient, TlsExtConfig, TlsNames},
    server::{parse_server_addrs, ShadowTlsServer, TlsAddrs},
};

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about,
    long_about = "A proxy to expose real tls handshake to the firewall.\nGithub: github.com/ihciah/shadow-tls"
)]
struct Args {
    #[clap(subcommand)]
    cmd: Commands,
    #[clap(flatten)]
    opts: Opts,
}

#[derive(Parser, Debug, Default, Clone)]
struct Opts {
    #[clap(short, long, help = "Set parallelism manually")]
    threads: Option<u8>,
    #[clap(short, long, help = "Disable TCP_NODELAY")]
    disable_nodelay: bool,
    #[clap(long, help = "Use v3 protocol")]
    v3: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[clap(about = "Run client side")]
    Client {
        #[clap(
            long = "listen",
            default_value = "[::1]:8080",
            help = "Shadow-tls client listen address(like \"[::1]:8080\")"
        )]
        listen: String,
        #[clap(
            long = "server",
            help = "Your shadow-tls server address(like \"1.2.3.4:443\")"
        )]
        server_addr: String,
        #[clap(
            long = "sni",
            help = "TLS handshake SNIs(like \"cloud.tencent.com\", \"captive.apple.com;cloud.tencent.com\")",
            value_parser = parse_client_names
        )]
        tls_names: TlsNames,
        #[clap(long = "password", help = "Password")]
        password: String,
        #[clap(
            long = "alpn",
            help = "Application-Layer Protocol Negotiation list(like \"http/1.1\", \"http/1.1;h2\")",
            value_delimiter = ';'
        )]
        alpn: Option<Vec<String>>,
    },
    #[clap(about = "Run server side")]
    Server {
        #[clap(
            long = "listen",
            default_value = "[::]:443",
            help = "Shadow-tls server listen address(like \"[::]:443\")"
        )]
        listen: String,
        #[clap(
            long = "server",
            help = "Your data server address(like \"127.0.0.1:8080\")"
        )]
        server_addr: String,
        #[clap(
            long = "tls",
            help = "TLS handshake server address(like \"cloud.tencent.com:443\", \"cloudflare.com:1.1.1.1:443;captive.apple.com;cloud.tencent.com\")",
            value_parser = parse_server_addrs
        )]
        tls_addr: TlsAddrs,
        #[clap(long = "password", help = "Password")]
        password: String,
    },
}

enum RunningArgs {
    Client {
        listen_addr: String,
        target_addr: String,
        tls_names: TlsNames,
        tls_ext: TlsExtConfig,
        password: String,
        nodelay: bool,
        v3: bool,
    },
    Server {
        listen_addr: String,
        target_addr: String,
        tls_addr: TlsAddrs,
        password: String,
        nodelay: bool,
        v3: bool,
    },
}

impl From<Args> for RunningArgs {
    fn from(args: Args) -> Self {
        match args.cmd {
            Commands::Client {
                listen,
                server_addr,
                tls_names,
                password,
                alpn,
            } => Self::Client {
                listen_addr: listen,
                target_addr: server_addr,
                tls_names,
                tls_ext: TlsExtConfig::from(alpn),
                password,
                nodelay: !args.opts.disable_nodelay,
                v3: args.opts.v3,
            },
            Commands::Server {
                listen,
                server_addr,
                tls_addr,
                password,
            } => Self::Server {
                listen_addr: listen,
                target_addr: server_addr,
                tls_addr,
                password,
                nodelay: !args.opts.disable_nodelay,
                v3: args.opts.v3,
            },
        }
    }
}

impl RunningArgs {
    fn build(self) -> anyhow::Result<Runnable<String, String>> {
        match self {
            RunningArgs::Client {
                listen_addr,
                target_addr,
                tls_names,
                tls_ext,
                password,
                nodelay,
                v3,
            } => Ok(Runnable::Client(ShadowTlsClient::new(
                listen_addr,
                target_addr,
                tls_names,
                tls_ext,
                password,
                nodelay,
                v3,
            )?)),
            RunningArgs::Server {
                listen_addr,
                target_addr,
                tls_addr,
                password,
                nodelay,
                v3,
            } => Ok(Runnable::Server(ShadowTlsServer::new(
                listen_addr,
                target_addr,
                tls_addr,
                password,
                nodelay,
                v3,
            ))),
        }
    }
}

impl Display for RunningArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client {
                listen_addr,
                target_addr,
                tls_names,
                tls_ext,
                nodelay,
                v3,
                ..
            } => {
                write!(f, "Client with:\nListen address: {listen_addr}\nTarget address: {target_addr}\nTLS server names: {tls_names}\nTLS Extension: {tls_ext}\nTCP_NODELAY: {nodelay}\nV3 Protocol: {v3}")
            }
            Self::Server {
                listen_addr,
                target_addr,
                tls_addr,
                nodelay,
                v3,
                ..
            } => {
                write!(f, "Server with:\nListen address: {listen_addr}\nTarget address: {target_addr}\nTLS server address: {tls_addr}\nTCP_NODELAY: {nodelay}\nV3 Protocol: {v3}")
            }
        }
    }
}

#[derive(Clone)]
enum Runnable<A, B> {
    Client(ShadowTlsClient<A, B>),
    Server(ShadowTlsServer<A, B>),
}

impl<A, B> Runnable<A, B>
where
    A: std::net::ToSocketAddrs + 'static,
    B: std::net::ToSocketAddrs + 'static,
{
    async fn serve(self) -> anyhow::Result<()> {
        match self {
            Runnable::Client(c) => c.serve().await,
            Runnable::Server(s) => s.serve().await,
        }
    }
}

fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive("rustls=off".parse().unwrap()),
        )
        .init();
    let args = sip003::get_sip003_arg().unwrap_or_else(Args::parse);
    let parallelism = get_parallelism(&args);
    let running_args = RunningArgs::from(args);
    tracing::info!("Start {parallelism}-thread {running_args}");

    let runnable = running_args.build().expect("unable to build runnable");
    let mut threads = Vec::new();
    for _ in 0..parallelism {
        let runnable_clone = runnable.clone();
        let t = std::thread::spawn(move || {
            let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                .enable_timer()
                .build()
                .expect("unable to build monoio runtime");
            let _ = rt.block_on(runnable_clone.serve());
        });
        threads.push(t);
    }
    if let Err(e) = ctrlc::set_handler(|| std::process::exit(0)) {
        tracing::error!("Unable to register signal handler: {e}");
    }
    threads.into_iter().for_each(|t| {
        let _ = t.join();
    });
}

fn get_parallelism(args: &Args) -> usize {
    if let Some(n) = args.opts.threads {
        return n as usize;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
