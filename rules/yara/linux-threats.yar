// Known Linux threats with distinctive strings. Same rule as linux-generic.yar: each one must stay quiet on a normal Arch
// desktop, so every rule needs a specific string, not just a suspicious word. Tests: crates/ai-antivirus-rules/tests/shipped_yara.rs.

rule php_webshell_eval_input {
  meta:
    severity = "high"
    description = "PHP that runs code taken straight from a web request (web shell)"
  strings:
    $php = "<?php" ascii nocase
    $e1 = /(eval|assert|system|passthru|shell_exec)\s*\(\s*(base64_decode\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE)\s*\[/ ascii nocase
    $e2 = /preg_replace\s*\(\s*['"]\/[^'"]*\/e['"]\s*,\s*\$_(POST|GET|REQUEST)/ ascii nocase
  condition:
    // a PHP file (the tag near the start, also after a fake GIF/PNG header), not a scanner or honeypot quoting one
    filesize < 1MB and $php in (0..512) and any of ($e*)
}

rule encoded_payload_to_shell {
  meta:
    severity = "medium"
    description = "Script that decodes a hidden payload and pipes it into a shell"
  strings:
    $b64 = /echo +['"]?[A-Za-z0-9+\/=]{40,}['"]? *\| *base64 +(-d|--decode)[^|\n]{0,20}\| *(\/(usr\/)?bin\/)?(ba)?sh\b/
    $xxd = /\| *xxd +-r +-p *\| *(\/(usr\/)?bin\/)?(ba)?sh\b/
  condition:
    filesize < 2MB and any of them
}

rule linux_lkm_rootkit_known {
  meta:
    severity = "critical"
    description = "Kernel-module rootkit with the strings of a public family (Diamorphine, Reptile)"
  strings:
    $d1 = "diamorphine_secret" ascii
    $d2 = "diamorphine" ascii
    $d3 = "hacked_kill" ascii
    $r1 = "reptile_shell" ascii
    $r2 = "/reptile/reptile_cmd" ascii
    $r3 = "reptile_module" ascii
  condition:
    uint32(0) == 0x464c457f and (2 of ($d*) or 2 of ($r*))
}

rule ssh_key_stealer_script {
  meta:
    severity = "high"
    description = "Script that collects SSH private keys and sends them to a remote host"
  strings:
    $k = /(cat|tar|find)[^\n]{0,80}\.ssh\/(id_(rsa|ed25519|ecdsa)|\*)/
    $send = /(curl +[^\n]{0,60}(-F|--data|-d|-T|--upload-file)|wget +[^\n]{0,60}--post-(file|data)|\| *nc +[0-9a-z.\-]+ +[0-9]{2,5})/
  condition:
    // a script (#! at the start), not documentation that shows such commands
    uint16(0) == 0x2123 and filesize < 1MB and $k and $send
}
