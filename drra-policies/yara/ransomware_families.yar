/*
 * DRRA - YARA Rules: Known Ransomware Family Signatures
 * Specific signatures for Ryuk, LockBit, Conti, BlackCat (ALPHV), and Hive.
 *
 * Sources: public threat intel, Any.run, MalwareBazaar, VirusTotal reports.
 * NOT for use in production without validation against your environment.
 */

// ---------------------------------------------------------------------------
// Ryuk
// ---------------------------------------------------------------------------
rule DRRA_Ryuk_Ransomware {
    meta:
        description = "Detects Ryuk ransomware indicators"
        author      = "DRRA"
        severity    = "critical"
        family      = "Ryuk"
        mitre       = "T1486, T1490"
        tags        = "ransomware, ryuk"

    strings:
        $s1 = "RyukReadMe.txt"     ascii wide nocase
        $s2 = "No system is safe"  ascii wide nocase
        $s3 = "HERMES"             ascii wide
        $s4 = ".ryk"               ascii wide nocase
        $s5 = "\\perfc"            ascii wide

        // Ryuk wallet address pattern (BTC)
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii

        // Known Ryuk mutex
        $mutex1 = "dfgdfg12121"    ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($s*) or
            ($btc and 1 of ($s*))
        )
}

// ---------------------------------------------------------------------------
// LockBit 3.0
// ---------------------------------------------------------------------------
rule DRRA_LockBit3_Ransomware {
    meta:
        description = "Detects LockBit 3.0 (LockBit Black) ransomware indicators"
        author      = "DRRA"
        severity    = "critical"
        family      = "LockBit"
        mitre       = "T1486, T1490, T1055"
        tags        = "ransomware, lockbit"

    strings:
        $note1 = "LockBit"               ascii wide nocase
        $note2 = "lockbit-decryptor"     ascii wide nocase
        $note3 = "lockbit.onion"         ascii wide nocase

        $ext1  = ".lockbit"              ascii wide nocase
        $ext2  = ".LockBit"              ascii wide

        // LockBit 3.0 ransom note header
        $hdr1  = "~~~ LockBit"           ascii wide nocase
        $hdr2  = "All of your files are stolen and encrypted" ascii wide nocase

        // Anti-analysis: VM/sandbox checks
        $vm1   = "VBoxService"           ascii wide nocase
        $vm2   = "vmtoolsd"              ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($note*) or
            1 of ($hdr*) or
            (1 of ($ext*) and 1 of ($note*))
        )
}

// ---------------------------------------------------------------------------
// Conti
// ---------------------------------------------------------------------------
rule DRRA_Conti_Ransomware {
    meta:
        description = "Detects Conti ransomware indicators"
        author      = "DRRA"
        severity    = "critical"
        family      = "Conti"
        mitre       = "T1486, T1490, T1021"
        tags        = "ransomware, conti"

    strings:
        $note1 = "CONTI_README.txt"       ascii wide nocase
        $note2 = "contirecovery@protonmail" ascii wide nocase
        $note3 = "Your data has been stolen" ascii wide nocase
        $note4 = ".CONTI"                 ascii wide

        // Conti uses Cobalt Strike beacons - beacon pattern
        $cs1   = "ReflectiveDll"          ascii wide nocase
        $cs2   = "beacon.dll"             ascii wide nocase

        // SMB lateral movement
        $smb1  = "\\\\*\\IPC$"           ascii wide
        $smb2  = "\\\\*\\ADMIN$"         ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($note*) or
            (1 of ($note*) and 1 of ($smb*))
        )
}

// ---------------------------------------------------------------------------
// BlackCat / ALPHV (Rust-based)
// ---------------------------------------------------------------------------
rule DRRA_BlackCat_ALPHV_Ransomware {
    meta:
        description = "Detects BlackCat / ALPHV ransomware (Rust-based, cross-platform)"
        author      = "DRRA"
        severity    = "critical"
        family      = "BlackCat"
        mitre       = "T1486, T1490, T1059"
        tags        = "ransomware, blackcat, alphv, rust"

    strings:
        $note1 = "RECOVER-"                           ascii wide nocase
        $note2 = "alphv"                              ascii wide nocase
        $note3 = "blackcat"                           ascii wide nocase
        $note4 = "Your network has been breached"     ascii wide nocase

        $ext1  = ".blackcat"                          ascii wide nocase
        $ext2  = ".sykffle"                           ascii wide nocase

        // Rust-specific strings
        $rust1 = "rust_begin_unwind"                  ascii wide
        $rust2 = "panicked at"                        ascii wide

        // BlackCat JSON config pattern
        $cfg1  = "\"encryption_key\""                 ascii wide
        $cfg2  = "\"targets\""                        ascii wide
        $cfg3  = "\"skip_hidden\""                    ascii wide

    condition:
        (
            2 of ($note*) or
            1 of ($ext*) or
            ($rust1 and $rust2 and 1 of ($cfg*))
        )
}

// ---------------------------------------------------------------------------
// Hive Ransomware
// ---------------------------------------------------------------------------
rule DRRA_Hive_Ransomware {
    meta:
        description = "Detects Hive ransomware indicators"
        author      = "DRRA"
        severity    = "critical"
        family      = "Hive"
        mitre       = "T1486, T1490"
        tags        = "ransomware, hive"

    strings:
        $note1 = "HOW_TO_DECRYPT.txt"    ascii wide nocase
        $note2 = "hive"                  ascii wide nocase
        $note3 = "Your network has been breached by Hive" ascii wide nocase

        $ext1  = ".hive"                 ascii wide nocase
        $ext2  = ".key.hive"             ascii wide nocase

        // Hive uses embedded key files
        $key1  = ".key."                 ascii wide
        $key2  = "key_file"              ascii wide nocase

    condition:
        (
            2 of ($note*) or
            1 of ($ext*) or
            (1 of ($note*) and 1 of ($key*))
        )
}

// ---------------------------------------------------------------------------
// Royal Ransomware
// ---------------------------------------------------------------------------
rule DRRA_Royal_Ransomware {
    meta:
        description = "Detects Royal ransomware indicators"
        author      = "DRRA"
        severity    = "critical"
        family      = "Royal"
        mitre       = "T1486, T1490"
        tags        = "ransomware, royal"

    strings:
        $note1 = "README.TXT"            ascii wide nocase
        $note2 = "royal"                 ascii wide nocase
        $note3 = "Your files are encrypted by Royal" ascii wide nocase

        $ext1  = ".royal"                ascii wide nocase
        $ext2  = ".royal_w"              ascii wide nocase

        // AES + RSA key embedding
        $key1  = "-----BEGIN RSA PUBLIC KEY-----" ascii
        $key2  = "-----BEGIN PUBLIC KEY-----"     ascii

    condition:
        (
            (1 of ($note*) and 1 of ($ext*)) or
            (2 of ($note*)) or
            (1 of ($ext*) and 1 of ($key*))
        )
}
