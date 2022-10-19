#![allow(stable_features)]
#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]

mod client;
mod server;
mod stream;
mod util;

use std::{rc::Rc, sync::Arc};

use clap::{Parser, Subcommand};
use monoio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*, EnvFilter};

use crate::{client::ShadowTlsClient, server::ShadowTlsServer, util::set_tcp_keepalive};

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
    #[clap(short, long)]
    threads: Option<u8>,
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
        #[clap(long = "sni", help = "TLS handshake SNI(like cloud.tencent.com)")]
        tls_name: String,
        #[clap(long = "password", help = "Password")]
        password: String,
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
            help = "TLS handshake server address(with port, like cloud.tencent.com:443)"
        )]
        tls_addr: String,
        #[clap(long = "password", help = "Password")]
        password: String,
    },
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
    let args = Arc::new(Args::parse());
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
            rt.block_on(run(args_clone));
        });
        threads.push(t);
    }
    threads.into_iter().for_each(|t| {
        let _ = t.join();
    });
}

fn get_parallelism(args: &Args) -> usize {
    if let Some(n) = args.threads {
        return n as usize;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

async fn run(cli: Arc<Args>) {
    match &cli.cmd {
        Commands::Client {
            listen,
            server_addr,
            tls_name,
            password,
        } => {
            run_client(
                listen.clone(),
                server_addr.clone(),
                tls_name.clone(),
                password.clone(),
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
            )
            .await
            .expect("server exited");
        }
    }
}

async fn run_client(
    listen: String,
    server_addr: String,
    tls_name: String,
    password: String,
) -> anyhow::Result<()> {
    info!("Client is running!\nListen address: {listen}\nRemote address: {server_addr}\nTLS server name: {tls_name}");
    let shadow_client = Rc::new(ShadowTlsClient::new(&tls_name, server_addr, password)?);
    let listener = TcpListener::bind(&listen)?;
    loop {
        match listener.accept().await {
            Ok((mut conn, addr)) => {
                info!("Accepted a connection from {addr}");
                let client = shadow_client.clone();
                set_tcp_keepalive(&mut conn);
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
    tls_addr: String,
    password: String,
) -> anyhow::Result<()> {
    info!("Server is running!\nListen address: {listen}\nRemote address: {server_addr}\nTLS server address: {tls_addr}");
    let shadow_server = Rc::new(ShadowTlsServer::new(tls_addr, server_addr, password));
    let listener = TcpListener::bind(&listen)?;
    loop {
        match listener.accept().await {
            Ok((mut conn, addr)) => {
                info!("Accepted a connection from {addr}");
                set_tcp_keepalive(&mut conn);
                let server = shadow_server.clone();
                monoio::spawn(async move { server.relay(conn).await });
            }
            Err(e) => {
                error!("Accept failed: {e}");
            }
        }
    }
}
