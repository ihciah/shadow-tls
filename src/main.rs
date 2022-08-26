mod protocol;

use std::{rc::Rc, sync::Arc};

use anyhow::Result;
use clap::{Parser, Subcommand};
use monoio::net::TcpListener;
use protocol::{ShadowTlsClient, ShadowTlsServer};
use tracing::{error, info, Level};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    cmd: Commands,
    #[clap(short, long)]
    threads: Option<u8>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Client {
        listen: String,
        server_addr: String,
        tls_name: String,
    },
    Server {
        listen: String,
        server_addr: String,
        tls_addr: String,
    },
}

fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    let cli = Arc::new(Args::parse());
    let mut threads = Vec::new();
    let parallelism = get_parallelism(&cli);
    info!("Started with parallelism {parallelism}");
    for _ in 0..parallelism {
        let cli_clone = cli.clone();
        let t = std::thread::spawn(move || {
            let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                .enable_timer()
                .build()
                .expect("unable to build monoio runtime");
            rt.block_on(run(cli_clone));
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
        } => {
            run_client(listen.clone(), server_addr.clone(), tls_name.clone())
                .await
                .expect("client exited");
        }
        Commands::Server {
            listen,
            server_addr,
            tls_addr,
        } => {
            run_server(listen.clone(), server_addr.clone(), tls_addr.clone())
                .await
                .expect("server exited");
        }
    }
}

async fn run_client(listen: String, server_addr: String, tls_name: String) -> Result<()> {
    info!("Client is running!\nListen address: {listen}\nRemote address: {server_addr}\nTLS server name: {tls_name}");
    let shadow_client = Rc::new(ShadowTlsClient::new(&tls_name, server_addr)?);
    let listener = TcpListener::bind(&listen)?;
    loop {
        match listener.accept().await {
            Ok((conn, addr)) => {
                info!("Accepted a connection from {addr}");
                let client = shadow_client.clone();
                monoio::spawn(async move { client.process(conn, addr).await });
            }
            Err(e) => {
                error!("Accept failed: {e}");
            }
        }
    }
}

async fn run_server(listen: String, server_addr: String, tls_addr: String) -> Result<()> {
    info!("Server is running!\nListen address: {listen}\nRemote address: {server_addr}\nTLS server address: {tls_addr}");
    let shadow_server = Rc::new(ShadowTlsServer::new(tls_addr, server_addr));
    let listener = TcpListener::bind(&listen)?;
    loop {
        match listener.accept().await {
            Ok((conn, addr)) => {
                info!("Accepted a connection from {addr}");
                let server = shadow_server.clone();
                monoio::spawn(async move { server.process(conn, addr).await });
            }
            Err(e) => {
                error!("Accept failed: {e}");
            }
        }
    }
}
