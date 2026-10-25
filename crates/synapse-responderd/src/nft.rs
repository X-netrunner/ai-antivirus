//! Network block (spec 8, level 5): Synapse's own nftables table `inet synapse` with one set per address family, each
//! element carrying its own timeout, and output/input chains that drop traffic to and from the set. Commands are JSON
//! documents built from typed values (`IpAddr`) and fed to `nft -j -f -` on stdin; nothing is ever passed through a
//! shell or formatted into nft's text syntax.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

pub const TABLE: &str = "synapse";
const NFT: &str = "/usr/bin/nft";

fn set_name(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "block4",
        IpAddr::V6(_) => "block6",
    }
}

fn drop_rule(chain: &str, proto: &str, field: &str, set: &str) -> Value {
    json!({"add": {"rule": {
        "family": "inet", "table": TABLE, "chain": chain,
        "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": field}}, "right": format!("@{set}")}},
            {"counter": null},
            {"drop": null}
        ]
    }}})
}

/// Create the table, sets, chains and rules in one transaction. Only used when the table does not exist yet (adding
/// rules is not idempotent).
pub fn create_table_doc() -> Value {
    let mut cmds = vec![
        json!({"add": {"table": {"family": "inet", "name": TABLE}}}),
        json!({"add": {"set": {"family": "inet", "table": TABLE, "name": "block4", "type": "ipv4_addr", "flags": ["timeout"]}}}),
        json!({"add": {"set": {"family": "inet", "table": TABLE, "name": "block6", "type": "ipv6_addr", "flags": ["timeout"]}}}),
        json!({"add": {"chain": {"family": "inet", "table": TABLE, "name": "output", "type": "filter", "hook": "output", "prio": -10, "policy": "accept"}}}),
        json!({"add": {"chain": {"family": "inet", "table": TABLE, "name": "input", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}}}),
    ];
    cmds.push(drop_rule("output", "ip", "daddr", "block4"));
    cmds.push(drop_rule("output", "ip6", "daddr", "block6"));
    cmds.push(drop_rule("input", "ip", "saddr", "block4"));
    cmds.push(drop_rule("input", "ip6", "saddr", "block6"));
    json!({"nftables": cmds})
}

pub fn add_element_doc(ip: IpAddr, ttl_secs: u32) -> Value {
    json!({"nftables": [{"add": {"element": {
        "family": "inet", "table": TABLE, "name": set_name(ip),
        "elem": [{"elem": {"val": ip.to_string(), "timeout": ttl_secs}}]
    }}}]})
}

pub fn delete_element_doc(ip: IpAddr) -> Value {
    json!({"nftables": [{"delete": {"element": {
        "family": "inet", "table": TABLE, "name": set_name(ip), "elem": [ip.to_string()]
    }}}]})
}

/// Runs nft. A trait so tests (and dry runs on machines without nftables) can record instead.
pub trait Nft: Send {
    /// Apply a JSON command document.
    fn apply(&self, doc: &Value) -> Result<(), String>;
    /// Does `inet synapse` exist?
    fn table_exists(&self) -> bool;
}

/// The real `nft` binary.
pub struct NftCmd;

impl Nft for NftCmd {
    fn apply(&self, doc: &Value) -> Result<(), String> {
        let mut child = Command::new(NFT)
            .args(["-j", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env_clear()
            .spawn()
            .map_err(|e| format!("cannot run {NFT}: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(doc.to_string().as_bytes())
                .map_err(|e| format!("cannot write to nft: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("nft failed: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            let msg = String::from_utf8_lossy(&out.stderr);
            Err(format!(
                "nft: {}",
                msg.trim().chars().take(400).collect::<String>()
            ))
        }
    }

    fn table_exists(&self) -> bool {
        Command::new(NFT)
            .args(["-j", "list", "table", "inet", TABLE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear()
            .status()
            .is_ok_and(|s| s.success())
    }
}

/// Block `ip` for `ttl_secs`, creating the table first when needed.
pub fn block(nft: &dyn Nft, ip: IpAddr, ttl_secs: u32) -> Result<(), String> {
    if !nft.table_exists() {
        nft.apply(&create_table_doc())?;
    }
    nft.apply(&add_element_doc(ip, ttl_secs))
}

/// Lift a block. An element that already expired is not an error.
pub fn unblock(nft: &dyn Nft, ip: IpAddr) -> Result<(), String> {
    if !nft.table_exists() {
        return Ok(());
    }
    match nft.apply(&delete_element_doc(ip)) {
        Ok(()) => Ok(()),
        Err(e) if e.contains("No such file or directory") => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Records every document; the table "exists" after a create.
    #[derive(Clone, Default)]
    pub struct FakeNft {
        pub docs: Arc<Mutex<Vec<Value>>>,
        pub fail: Arc<Mutex<Option<String>>>,
    }

    impl Nft for FakeNft {
        fn apply(&self, doc: &Value) -> Result<(), String> {
            if let Some(e) = self.fail.lock().unwrap().clone() {
                return Err(e);
            }
            self.docs.lock().unwrap().push(doc.clone());
            Ok(())
        }

        fn table_exists(&self) -> bool {
            self.docs
                .lock()
                .unwrap()
                .iter()
                .any(|d| d["nftables"][0]["add"].get("table").is_some())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeNft;
    use super::*;

    #[test]
    fn documents_are_typed_json() {
        let d = add_element_doc("203.0.113.9".parse().unwrap(), 3600);
        let e = &d["nftables"][0]["add"]["element"];
        assert_eq!(e["name"], "block4");
        assert_eq!(e["elem"][0]["elem"]["val"], "203.0.113.9");
        assert_eq!(e["elem"][0]["elem"]["timeout"], 3600);
        let d6 = delete_element_doc("2001:db8::7".parse().unwrap());
        assert_eq!(d6["nftables"][0]["delete"]["element"]["name"], "block6");
        let t = create_table_doc();
        assert_eq!(t["nftables"].as_array().unwrap().len(), 9);
        assert_eq!(
            t["nftables"][5]["add"]["rule"]["expr"][0]["match"]["right"],
            "@block4"
        );
    }

    #[test]
    fn block_creates_the_table_once() {
        let nft = FakeNft::default();
        block(&nft, "198.51.100.1".parse().unwrap(), 60).unwrap();
        block(&nft, "198.51.100.2".parse().unwrap(), 60).unwrap();
        let docs = nft.docs.lock().unwrap().clone();
        assert_eq!(docs.len(), 3, "create, add, add");
        drop(docs);
        unblock(&nft, "198.51.100.1".parse().unwrap()).unwrap();
        *nft.fail.lock().unwrap() =
            Some("Error: Could not process rule: No such file or directory".into());
        unblock(&nft, "198.51.100.1".parse().unwrap()).unwrap();
        *nft.fail.lock().unwrap() = Some("Error: Operation not permitted".into());
        assert!(unblock(&nft, "198.51.100.1".parse().unwrap()).is_err());
    }
}
