/*
 * DRRA - YARA Rules: Generic Ransomware Indicators
 * Detects common ransomware behaviors, API patterns, and code signatures.
 * Compatible with: ClamAV, Kaspersky, CrowdStrike, Carbon Black, Velociraptor
 *
 * References:
 *   - MITRE ATT&CK T1486 (Data Encrypted for Impact)
 *   - MITRE ATT&CK T1490 (Inhibit System Recovery)
 */

import "pe"
import "hash"

// ---------------------------------------------------------------------------
// Ransom Note File Names
// ---------------------------------------------------------------------------
rule DRRA_RansomNote_Filenames {
    meta:
        description = "Detects common ransom note filenames dropped on disk"
        author      = "DRRA"
        severity    = "high"
        mitre       = "T1486"
        tags        = "ransomware, ransom-note"

    strings:
        $n1  = "HOW_TO_DECRYPT" ascii wide nocase
        $n2  = "DECRYPT_FILES" ascii wide nocase
        $n3  = "READ_ME_FOR_DECRYPT" ascii wide nocase
        $n4  = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase
        $n5  = "RECOVERY_INSTRUCTIONS" ascii wide nocase
        $n6  = "RESTORE_FILES" ascii wide nocase
        $n7  = "FILES_ENCRYPTED" ascii wide nocase
        $n8  = "HOW_TO_RESTORE" ascii wide nocase
        $n9  = "!!! IMPORTANT !!!" ascii wide nocase
        $n10 = "ransom" ascii wide nocase

    condition:
        any of ($n*)
}

// ---------------------------------------------------------------------------
// Encryption API Usage (Windows CryptoAPI / BCrypt)
// ---------------------------------------------------------------------------
rule DRRA_CryptoAPI_Ransomware {
    meta:
        description = "Detects PE files using Windows cryptographic APIs typical of ransomware"
        author      = "DRRA"
        severity    = "high"
        mitre       = "T1486"
        tags        = "ransomware, cryptoapi, encryption"

    strings:
        $api1 = "CryptEncrypt"         ascii wide
        $api2 = "BCryptEncrypt"        ascii wide
        $api3 = "CryptGenKey"          ascii wide
        $api4 = "BCryptGenerateSymmetricKey" ascii wide
        $api5 = "CryptAcquireContext"  ascii wide
        $api6 = "CryptImportKey"       ascii wide

        // Key exchange patterns
        $kex1 = "CryptExportKey"       ascii wide
        $kex2 = "BCryptExportKey"      ascii wide

    condition:
        uint16(0) == 0x5A4D and  // PE magic
        (
            (2 of ($api*) and 1 of ($kex*)) or
            3 of ($api*)
        )
}

// ---------------------------------------------------------------------------
// Shadow Copy Deletion (VSS Abuse)
// ---------------------------------------------------------------------------
rule DRRA_VSS_Deletion {
    meta:
        description = "Detects commands or code that delete Volume Shadow Copies"
        author      = "DRRA"
        severity    = "critical"
        mitre       = "T1490"
        tags        = "ransomware, vss, inhibit-recovery"

    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe delete"     ascii wide nocase
        $vss3 = "wmic shadowcopy delete"  ascii wide nocase
        $vss4 = "Win32_ShadowCopy"        ascii wide nocase
        $vss5 = "bcdedit /set"            ascii wide nocase
        $vss6 = "recoveryenabled no"      ascii wide nocase
        $vss7 = "ignoreallfailures"       ascii wide nocase
        $vss8 = "wbadmin delete catalog"  ascii wide nocase

    condition:
        any of ($vss*)
}

// ---------------------------------------------------------------------------
// File Extension Renaming Loops (bulk rename patterns)
// ---------------------------------------------------------------------------
rule DRRA_BulkRename_Behavior {
    meta:
        description = "Detects code patterns consistent with bulk file renaming (ransomware encryption loop)"
        author      = "DRRA"
        severity    = "high"
        mitre       = "T1486"
        tags        = "ransomware, file-rename, encryption-loop"

    strings:
        // Common known ransomware extensions
        $ext1  = ".locked"   ascii wide nocase
        $ext2  = ".enc"      ascii wide nocase
        $ext3  = ".encrypted" ascii wide nocase
        $ext4  = ".crypto"   ascii wide nocase
        $ext5  = ".crypt"    ascii wide nocase
        $ext6  = ".ryk"      ascii wide nocase   // Ryuk
        $ext7  = ".RYK"      ascii wide
        $ext8  = ".conti"    ascii wide nocase
        $ext9  = ".hive"     ascii wide nocase   // Hive
        $ext10 = ".blackcat" ascii wide nocase   // ALPHV/BlackCat
        $ext11 = ".ALPHV"    ascii wide
        $ext12 = ".LockBit"  ascii wide nocase
        $ext13 = ".lockbit"  ascii wide nocase

        // File manipulation APIs
        $api1 = "MoveFileExW"  ascii wide
        $api2 = "MoveFileExA"  ascii wide
        $api3 = "SetFileAttributesW" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        2 of ($ext*) and
        1 of ($api*)
}

// ---------------------------------------------------------------------------
// Network Enumeration (precursor to lateral movement)
// ---------------------------------------------------------------------------
rule DRRA_NetworkEnum_Ransomware {
    meta:
        description = "Detects network enumeration techniques used before ransomware deployment"
        author      = "DRRA"
        severity    = "medium"
        mitre       = "T1018"
        tags        = "ransomware, lateral-movement, recon"

    strings:
        $net1 = "NetShareEnum"       ascii wide
        $net2 = "WNetOpenEnum"       ascii wide
        $net3 = "WNetEnumResource"   ascii wide
        $net4 = "GetTcpTable"        ascii wide
        $net5 = "\\\\*"              ascii wide   // UNC path pattern

        $cmd1 = "net view"           ascii wide nocase
        $cmd2 = "net use"            ascii wide nocase
        $cmd3 = "nltest /domain"     ascii wide nocase
        $cmd4 = "arp -a"             ascii wide nocase

    condition:
        2 of ($net*) or
        2 of ($cmd*)
}

// ---------------------------------------------------------------------------
// Credential Harvesting (common pre-encryption step)
// ---------------------------------------------------------------------------
rule DRRA_CredentialHarvest {
    meta:
        description = "Detects LSASS dumping or credential harvesting techniques"
        author      = "DRRA"
        severity    = "critical"
        mitre       = "T1003"
        tags        = "ransomware, credential-theft, lsass"

    strings:
        $lsass1 = "lsass.exe"            ascii wide nocase
        $lsass2 = "MiniDumpWriteDump"    ascii wide
        $lsass3 = "NtReadVirtualMemory"  ascii wide
        $lsass4 = "OpenProcess"          ascii wide

        $mimi1  = "sekurlsa"             ascii wide nocase
        $mimi2  = "logonpasswords"       ascii wide nocase
        $mimi3  = "privilege::debug"     ascii wide nocase

        $sam1   = "\\SAM"                ascii wide
        $sam2   = "\\SYSTEM"             ascii wide
        $sam3   = "\\SECURITY"           ascii wide

    condition:
        (
            ($lsass1 and 2 of ($lsass2, $lsass3, $lsass4)) or
            any of ($mimi*) or
            (all of ($sam*))
        )
}

// ---------------------------------------------------------------------------
// Self-Deletion / Anti-Forensics
// ---------------------------------------------------------------------------
rule DRRA_AntiForensics {
    meta:
        description = "Detects self-deletion or log clearing to hinder forensic analysis"
        author      = "DRRA"
        severity    = "high"
        mitre       = "T1070"
        tags        = "ransomware, anti-forensics, log-clearing"

    strings:
        $del1 = "cmd /c del"          ascii wide nocase
        $del2 = "DeleteFileW"         ascii wide
        $del3 = "DeleteFileA"         ascii wide

        $log1 = "wevtutil cl"         ascii wide nocase
        $log2 = "ClearEventLog"       ascii wide
        $log3 = "wevtutil.exe"        ascii wide nocase
        $log4 = "Clear-EventLog"      ascii wide nocase

        $reg1 = "reg delete"          ascii wide nocase

    condition:
        (1 of ($del*) and 1 of ($log*)) or
        2 of ($log*) or
        ($del1 and $reg1)
}
