rule ETAS_Synthetic_Fixture
{
    meta:
        description = "Matches the inert ETAS test fixture string. Not a real malware family rule."
        author = "ETAS"
    strings:
        $a = "ETAS-TEST-MALICIOUS-HASH-FIXTURE"
    condition:
        $a
}
