#![allow(stable_features)]
#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]

mod client;
mod server;
mod sip003;
mod stream;
mod util;

use std::{fmt::Display, rc::Rc, sync::Arc};

use clap::{Parser, Subcommand};
use monoio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*, EnvFilter};

use crate::{
    client::{parse_client_names, ShadowTlsClient, TlsExtConfig, TlsNames},
    server::{parse_server_addrs, ShadowTlsServer, TlsAddrs},
    util::mod_tcp_conn,
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
pub struct Opts {
    #[clap(short, long, help = "Set parallelism manually")]
    threads: Option<u8>,
    #[clap(short, long, help = "Disable TCP_NODELAY")]
    disable_nodelay: bool,
}

impl Display for Opts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.threads {
            Some(t) => {
                write!(f, "fixed {t} threads")
            }
            None => {
                write!(f, "auto adjusted threads")
            }
        }?;
        write!(f, "; nodelay: {}", !self.disable_nodelay)
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[clap(about = "Run client side")]
    Client {
        #[clap(
            long = "listen",
            default_value = "[::1]:8080",
            help = "Shadow-tls client listen address"
        )]
        listen: String,
        #[clap(
            long = "server",
            help = "Your shadow-tls server address(like 1.2.3.4:443)"
        )]
        server_addr: String,
        #[clap(
            long = "sni",
            help = "TLS handshake SNI(like cloud.tencent.com, captive.apple.com;cloud.tencent.com)",
            value_parser = parse_client_names
        )]
        tls_names: TlsNames,
        #[clap(long = "password", help = "Password")]
        password: String,
        #[clap(
            long = "alpn",
            help = "Application-Layer Protocol Negotiation(like \"http/1.1\")"
        )]
        alpn: Option<String>,
    },
    #[clap(about = "Run server side")]
    Server {
        #[clap(
            long = "listen",
            default_value = "[::1]:443",
            help = "Shadow-tls server listen address"
        )]
        listen: String,
        #[clap(
            long = "server",
            help = "Your data server address(like 127.0.0.1:8080)"
        )]
        server_addr: String,
        #[clap(
            long = "tls",
            help = "TLS handshake server address(like cloud.tencent.com:443, cloudflare.com:1.1.1.1:443;captive.apple.com;cloud.tencent.com)",
            value_parser = parse_server_addrs
        )]
        tls_addr: TlsAddrs,
        #[clap(long = "password", help = "Password")]
        password: String,
    },
}

impl Args {
    async fn start(&self) {
        match &self.cmd {
            Commands::Client {
                listen,
                server_addr,
                tls_names,
                password,
                alpn,
            } => {
                run_client(
                    listen.clone(),
                    server_addr.clone(),
                    tls_names.clone(),
                    password.clone(),
                    self.opts.clone(),
                    TlsExtConfig::new(alpn.clone().map(|alpn| vec![alpn.into_bytes()])),
                )
                .await
                .expect("client exited");
            }
            Commands::Server {
                listen,
                server_addr,
                tls_addr,
                password,
            } => {
                run_server(
                    listen.clone(),
                    server_addr.clone(),
                    tls_addr.clone(),
                    password.clone(),
                    self.opts.clone(),
                )
                .await
                .expect("server exited");
            }
        }
    }
}

fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    let args = match sip003::get_sip003_arg() {
        Some(a) => Arc::new(a),
        None => Arc::new(Args::parse()),
    };
    let mut threads = Vec::new();
    let parallelism = get_parallelism(&args);
    info!("Started with parallelism {parallelism}");
    for _ in 0..parallelism {
        let args_clone = args.clone();
        let t = std::thread::spawn(move || {
            let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                .enable_timer()
                .build()
                .expect("unable to build monoio runtime");
            rt.block_on(args_clone.start());
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

async fn run_client(
    listen: String,
    server_addr: String,
    tls_names: TlsNames,
    password: String,
    opts: Opts,
    tls_ext: TlsExtConfig,
) -> anyhow::Result<()> {
    info!("Client is running!\nListen address: {listen}\nRemote address: {server_addr}\nTLS server names: {tls_names}\nOpts: {opts}");
    let nodelay = !opts.disable_nodelay;
    let shadow_client = Rc::new(ShadowTlsClient::new(
        tls_names,
        server_addr,
        password,
        opts,
        tls_ext,
    )?);
    let listener = TcpListener::bind(&listen)?;
    loop {
        match listener.accept().await {
            Ok((mut conn, addr)) => {
                info!("Accepted a connection from {addr}");
                let client = shadow_client.clone();
                mod_tcp_conn(&mut conn, true, nodelay);
                monoio::spawn(async move { client.relay(conn, addr).await });
            }
            Err(e) => {
                error!("Accept failed: {e}");
            }
        }
    }
}

async fn run_server(
    listen: String,
    server_addr: String,
    tls_addr: TlsAddrs,
    password: String,
    opts: Opts,
) -> anyhow::Result<()> {
    info!("Server is running!\nListen address: {listen}\nRemote address: {server_addr}\nTLS server address: {tls_addr}\nOpts: {opts}");
    let nodelay = !opts.disable_nodelay;
    let shadow_server = Rc::new(ShadowTlsServer::new(tls_addr, server_addr, password, opts));
    let listener = TcpListener::bind(&listen)
        .map_err(|e| anyhow::anyhow!("bind failed, check if the port is used: {e}"))?;
    loop {
        match listener.accept().await {
            Ok((mut conn, addr)) => {
                info!("Accepted a connection from {addr}");
                mod_tcp_conn(&mut conn, true, nodelay);
                let server = shadow_server.clone();
                monoio::spawn(async move { server.relay(conn).await });
            }
            Err(e) => {
                error!("Accept failed: {e}");
            }
        }
    }
}
