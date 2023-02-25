use anyhow::{bail, Context};

// Parse SIP003 optinos from env
pub fn parse_sip003_options(s: &str) -> Result<Vec<(String, String)>, anyhow::Error> {
    let mut opts = vec![];
    let mut i = 0;
    while i < s.len() {
        // read key
        let (offset, key) = index_unescaped(&s[i..], &[b'=', b';']).context("read key")?;
        if key.is_empty() {
            bail!("empty key in {}", &s[i..]);
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
                bail!("nothing following final escape in {s}",);
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
