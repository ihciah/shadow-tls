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
    pub fn build(self) -> anyhow::Result<Runnable> {
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
                fastopen,
                v3,
                ..
            } => {
                write!(f, "Client with:\nListen address: {listen_addr}\nTarget address: {target_addr}\nTLS server names: {tls_names}\nTLS Extension: {tls_ext}\nTCP_NODELAY: {nodelay}\nTCP_FASTOPEN:{fastopen}\nV3 Protocol: {v3}")
            }
            Self::Server {
                listen_addr,
                target_addr,
                tls_addr,
                nodelay,
                fastopen,
                v3,
                ..
            } => {
                write!(f, "Server with:\nListen address: {listen_addr}\nTarget address: {target_addr}\nTLS server address: {tls_addr}\nTCP_NODELAY: {nodelay}\nTCP_FASTOPEN:{fastopen}\nV3 Protocol: {v3}")
            }
        }
    }
}

#[derive(Clone)]
pub enum Runnable {
    Client(ShadowTlsClient),
    Server(ShadowTlsServer),
}

impl Runnable {
    async fn serve(self) -> anyhow::Result<()> {
        match self {
            Runnable::Client(c) => c.serve().await,
            Runnable::Server(s) => s.serve().await,
        }
    }

    pub fn start(&self, parallelism: usize) -> Vec<JoinHandle<anyhow::Result<()>>> {
        // 8 threads are enough for resolving domains
        const MAX_BLOCKING_THREADS: usize = 8;

        let mut threads = Vec::new();
        let shared_pool =
            monoio::blocking::DefaultThreadPool::new(MAX_BLOCKING_THREADS.min(2 * parallelism));
        for _ in 0..parallelism {
            let runnable_clone = self.clone();
            let shared_pool = Box::new(shared_pool.clone());
            let t = std::thread::spawn(move || {
                let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                .attach_thread_pool(shared_pool)
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
