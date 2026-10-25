// The EICAR anti-virus test file (harmless; every scanner reports it). Used to check the signature path end to end.
rule eicar_test_file {
  meta:
    severity = "low"
    description = "EICAR anti-virus test file"
  strings:
    $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $e at 0
}
