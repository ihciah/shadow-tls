use anyhow::Context;
use tracing::error;

use super::Args;
use std::{collections::HashMap, env, process::exit};

macro_rules! env {
    ($key: expr) => {
        match env::var($key).ok() {
            None => return None,
            Some(val) if val.is_empty() => return None,
            Some(val) => val,
        }
    };
    ($key: expr, $fail_fn: expr) => {
        match env::var($key).ok() {
            None => return None,
            Some(val) if val.is_empty() => {
                $fail_fn();
                return None;
            }
            Some(val) => val,
        }
    };
}

// SIP003 [https://shadowsocks.org/en/wiki/Plugin.html](https://shadowsocks.org/en/wiki/Plugin.html)
pub(crate) fn get_sip003_arg() -> Option<Args> {
    let ss_remote_host = env!("SS_REMOTE_HOST");
    let ss_remote_port = env!("SS_REMOTE_PORT");
    let ss_local_host = env!("SS_LOCAL_HOST");
    let ss_local_port = env!("SS_LOCAL_PORT");
    let ss_plugin_options = env!("SS_PLUGIN_OPTIONS", || {
        error!("need SS_PLUGIN_OPTIONS when as SIP003 plugin");
        exit(-1);
    });

    let opts = parse_sip003_options(&ss_plugin_options).unwrap();
    let opts: HashMap<_, _> = opts.into_iter().collect();

    let threads = opts.get("threads").map(|s| s.parse::<u8>().unwrap());
    let passwd = opts
        .get("passwd")
        .expect("need passwd param(like passwd=123456)");

    let args_opts = crate::Opts {
        threads,
        ..Default::default()
    };
    let args = if opts.get("server").is_some() {
        let tls_addr = opts
            .get("tls")
            .expect("need tls param(like tls=xxx.com:443)");
        Args {
            cmd: crate::Commands::Server {
                listen: format!("{ss_remote_host}:{ss_remote_port}"),
                server_addr: format!("{ss_local_host}:{ss_local_port}"),
                tls_addr: tls_addr.to_owned(),
                password: passwd.to_owned(),
            },
            opts: args_opts,
        }
    } else {
        let host = opts
            .get("host")
            .expect("need host param(like host=www.baidu.com)");
        Args {
            cmd: crate::Commands::Client {
                listen: format!("{ss_local_host}:{ss_local_port}"),
                server_addr: format!("{ss_remote_host}:{ss_remote_port}"),
                tls_name: host.to_owned(),
                password: passwd.to_owned(),
                alpn: Default::default(),
            },
            opts: args_opts,
        }
    };
    Some(args)
}

// Parse SIP003 optinos from env
fn parse_sip003_options(s: &str) -> Result<Vec<(String, String)>, anyhow::Error> {
    let mut opts = vec![];
    let mut i = 0;
    while i < s.len() {
        // read key
        let (offset, key) = index_unescaped(&s[i..], &[b'=', b';']).context("read key")?;
        if key.is_empty() {
            return Err(anyhow::format_err!("empty key in {}", &s[i..]));
        }
        i += offset;
        // end of string or no equals sign
        if i >= s.len() || s.as_bytes()[i] != b'=' {
            opts.push((key, "1".to_string()));
            i += 1;
            continue;
        }

        // skip equals
        i += 1;
        // read value
        let (offset, value) = index_unescaped(&s[i..], &[b'=', b';']).context("read value")?;
        i += offset;
        opts.push((key, value));
        // Skip the semicolon.
        i += 1;
    }
    Ok(opts)
}

fn index_unescaped(s: &str, term: &[u8]) -> Result<(usize, String), anyhow::Error> {
    let mut i = 0;
    let mut unesc = vec![];

    while i < s.len() {
        let mut b: u8 = s.as_bytes()[i];
        if let Some(..) = term.iter().find(|&&e| b == e) {
            break;
        }
        if b == b'\\' {
            i += 1;
            if i >= s.len() {
                return Err(anyhow::format_err!(
                    "nothing following final escape in {}",
                    s
                ));
            }
            b = s.as_bytes()[i];
        }
        unesc.push(b);
        i += 1;
    }
    Ok((i, String::from_utf8(unesc).unwrap()))
}

#[cfg(test)]
#[test]
fn test_parse_sip003_options() {
    let ret = parse_sip003_options("server;secret=\\=nou;cache=/tmp/cache;secret=yes").unwrap();
    assert!(ret.len() == 4);
    assert_eq!(
        ret,
        vec![
            ("server".to_string(), "1".to_string()),
            ("secret".to_string(), "=nou".to_string()),
            ("cache".to_string(), "/tmp/cache".to_string()),
            ("secret".to_string(), "yes".to_string()),
        ]
    );
}
