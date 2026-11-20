rule EICAR_Test_Dosyasi {
    meta:
        description = "Standart EICAR Antivirus Test Imzasi"
        severity = "High"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Gizli_Calistirilabilir_Dosya_MZ {
    meta:
        description = "Windows PE/EXE basligi (MZ) tespit edildi"
        severity = "High"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Supheli_Betik_Komutlari {
    meta:
        description = "Supheli PowerShell veya sistem komutu iceriyor"
        severity = "Critical"
    strings:
        $s1 = "powershell" nocase
        $s2 = "-encodedcommand" nocase
        $s3 = "Invoke-WebRequest" nocase
        $s4 = "cmd.exe /c" nocase
        $s5 = "WScript.Shell" nocase
    condition:
        2 of them
}