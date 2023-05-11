#![feature(impl_trait_in_assoc_type)]

mod client;
mod helper_v2;
mod server;
pub mod sip003;
mod util;

use std::{fmt::Display, thread::JoinHandle};

pub use crate::{
    client::{ShadowTlsClient, TlsExtConfig, TlsNames},
    server::{ShadowTlsServer, TlsAddrs},
    util::{V3Mode, WildcardSNI},
};

pub enum RunningArgs {
    Client {
        listen_addr: String,
        target_addr: String,
        tls_names: TlsNames,
        tls_ext: TlsExtConfig,
        password: String,
        nodelay: bool,
        fastopen: bool,
        v3: V3Mode,
    },
    Server {
        listen_addr: String,
        target_addr: String,
        tls_addr: TlsAddrs,
        password: String,
        nodelay: bool,
        fastopen: bool,
        v3: V3Mode,
    },
}

impl RunningArgs {
    #[inline]
    pub fn build(self) -> anyhow::Result<Runnable<String, String>> {
        match self {
            RunningArgs::Client {
                listen_addr,
                target_addr,
                tls_names,
                tls_ext,
                password,
                nodelay,
                fastopen,
                v3,
            } => Ok(Runnable::Client(ShadowTlsClient::new(
                listen_addr,
                target_addr,
                tls_names,
                tls_ext,
                password,
                nodelay,
                fastopen,
                v3,
            )?)),
            RunningArgs::Server {
                listen_addr,
                target_addr,
                tls_addr,
                password,
                nodelay,
                fastopen,
                v3,
            } => Ok(Runnable::Server(ShadowTlsServer::new(
                listen_addr,
                target_addr,
                tls_addr,
                password,
                nodelay,
                fastopen,
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
pub enum Runnable<A, B> {
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

    pub fn start(&self, parallelism: usize) -> Vec<JoinHandle<anyhow::Result<()>>>
    where
        A: Clone + Send + Sync,
        B: Clone + Send + Sync,
    {
        let mut threads = Vec::new();
        for _ in 0..parallelism {
            let runnable_clone = self.clone();
            let t = std::thread::spawn(move || {
                let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                .enable_timer()
                .build()
                .expect("unable to build monoio runtime(please refer to: https://github.com/ihciah/shadow-tls/wiki/How-to-Run#common-issues)");
                rt.block_on(runnable_clone.serve())
            });
            threads.push(t);
        }
        threads
    }
}
