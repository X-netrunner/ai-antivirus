// Generic Linux indicators in scripts and binaries. Kept narrow on purpose: every rule here has to stay quiet on a normal
// Arch desktop (see README "M3: false positives"). Severity meta sets the alert severity.

rule reverse_shell_oneliner {
  meta:
    severity = "high"
    description = "Script with a classic reverse-shell one-liner"
  strings:
    $bash_tcp = /(bash|sh) -i *>& *\/dev\/tcp\/[0-9a-zA-Z.\-]+\/[0-9]{1,5}/
    $nc_e = /\bnc(at)? +(-[a-z]+ +)*-e +\/(usr\/)?bin\/(ba)?sh/
    $py_pty = /import socket,(subprocess|os),(os|subprocess|pty)/
    $mkfifo = /mkfifo +\/tmp\/[a-z]+;.*\| *\/(usr\/)?bin\/sh -i/
  condition:
    filesize < 2MB and any of them
}

rule cryptominer_xmrig {
  meta:
    severity = "medium"
    description = "XMRig-style cryptominer (stratum pool and miner strings)"
  strings:
    $s1 = "stratum+tcp://" ascii
    $s2 = "stratum+ssl://" ascii
    $x1 = "xmrig" ascii nocase
    $x2 = "randomx" ascii nocase
    $x3 = "\"donate-level\"" ascii
  condition:
    any of ($s*) and 2 of ($x*)
}

rule ld_preload_rootkit_hint {
  meta:
    severity = "high"
    description = "Library that hides itself via ld.so.preload and readdir hooks"
  strings:
    $p = "/etc/ld.so.preload" ascii
    $r1 = "readdir64" ascii
    $r2 = "readdir" ascii
    $h = "dlsym" ascii
  condition:
    uint32(0) == 0x464c457f and $p and $h and any of ($r*)
}
