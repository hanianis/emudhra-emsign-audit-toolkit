# =========================================================================
# PowerShell Certificate Audit - eMudhra / emSign & Sectigo Cross-Sign
# Purpose: Detect compromised eMudhra intermediates (8 SPKI keys / 16 certs)
#          and vulnerable "Shadow Trust" Root CA bundles (CVE-2026-111943)
# =========================================================================


# -------------------- Config --------------------------

$VerboseMode           = $true   # Set $false for silent execution
$SummaryMode           = $true
$EnableSCCM            = $true
$IncludeSectigoAaaRoot = $false   

# 1. COMPROMISED INTERMEDIATE PUBLIC KEYS (SPKI SHA-256)
# Covers all 16 Intermediate Certificates (8 emSign Native + 8 Sectigo Cross-Signed)
$CompromisedSpkiHashes = @{
    "EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105" = "EM DV TLS CA - G3B (TLS DV)"
    "49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F" = "EM DV TLS CA - G3C (TLS DV)"
    "E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41" = "EM EV TLS CA - G3B (TLS EV)"
    "5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0" = "EM EV TLS CA - G3C (TLS EV)"
    "43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B" = "EM OV TLS CA - G3B (TLS OV)"
    "63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8" = "EM OV TLS CA - G3C (TLS OV)"
    "EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6" = "EM OV CS CA - G3B (Code Signing)"
    "92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30" = "EM OV CS CA - G3C (Code Signing)"
}

# 2. COMPROMISED INTERMEDIATE CERTIFICATE SHA-256 FINGERPRINTS (Direct Cert Match)
$CompromisedCertHashes = @{
    # "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493" = "EM DV TLS CA - G3B (Native emSign)"
    # "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE" = "EM DV TLS CA - G3B (Sectigo Cross-Sign)"
    # "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19" = "EM DV TLS CA - G3C (Native emSign)"
    # "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838" = "EM EV TLS CA - G3B (Native emSign)"
    # "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3" = "EM EV TLS CA - G3C (Native emSign)"
    # "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B" = "EM OV TLS CA - G3B (Native emSign)"
    # "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F" = "EM OV TLS CA - G3C (Native emSign)"
    # "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4" = "EM OV CS CA - G3B (Native emSign)"
    # "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1" = "EM OV CS CA - G3C (Native emSign)"
}

# 3. SHADOW TRUST ROOT CA FINGERPRINTS (Certificate SHA-256)
$ShadowTrustRootHashes = @{
    "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B" = "emSign ECC Root CA - G3 (Distrusted Root)"
    # "7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D" = "emSign Root TLS CA - G3 (Direct TLS Root)"
    # "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5" = "emSign Root CS CA - G3 (Direct Code Signing Root)"
}
if ($IncludeSectigoAaaRoot) {
    $ShadowTrustRootHashes["D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4"] = "AAA Certificate Services (Sectigo Cross-Signing Root)"
}

$SearchPaths = @(
    "C:\Program Files (x86)",
    "C:\Program Files",
    "C:\ProgramData",
    "C:\Users",
    "C:\tools",
    "C:\inetpub"
)


$FileNameRegex = [regex]::new('(?i)(\.(pem|crt|cer|bundle)$|ca-bundle|cacert|^blocked\.certs$|^blacklisted\.certs$)', [System.Text.RegularExpressions.RegexOptions]::Compiled)

$Findings            = [System.Collections.Generic.List[PSCustomObject]]::new()
$ScanErrors          = [System.Collections.Generic.List[String]]::new()
$ScannedFiles        = 0
$CertificatesChecked = 0
$PathsScanned        = 0

$Sha256Hasher = [System.Security.Cryptography.SHA256]::Create()
$PemRegex     = [regex]::new('(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', [System.Text.RegularExpressions.RegexOptions]::Compiled)


$P384SpkiPrefix = [byte[]](0x30,0x76,0x30,0x10,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,0x06,0x05,0x2B,0x81,0x04,0x00,0x22,0x03,0x62,0x00)

function Get-MatchingFiles {
    param ([string]$RootPath)

    $Stack = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
    try {
        $Stack.Push([System.IO.DirectoryInfo]::new($RootPath))
    } catch {
        $script:ScanErrors.Add("Cannot initialize directory ${RootPath}: $($_.Exception.Message)")
        return
    }

    while ($Stack.Count -gt 0) {
        $CurrentDir = $Stack.Pop()
        
        try {
            foreach ($File in $CurrentDir.EnumerateFiles()) {
                if ($FileNameRegex.IsMatch($File.Name)) {
                    $File
                }
            }
        } catch {
            $script:ScanErrors.Add("File enumeration error in $($CurrentDir.FullName): $($_.Exception.Message)")
        }

        try {
            foreach ($SubDir in $CurrentDir.EnumerateDirectories()) {
                if (($SubDir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
                    $Stack.Push($SubDir)
                }
            }
        } catch {
            $script:ScanErrors.Add("Directory access denied in $($CurrentDir.FullName): $($_.Exception.Message)")
        }
    }
}

function Get-CertSpkiSha256 {
    param ([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    try {
        if ($Cert.PublicKey | Get-Member -Name "ExportSubjectPublicKeyInfo" -MemberType Method) {
            $SpkiBytes = $Cert.PublicKey.ExportSubjectPublicKeyInfo()
            return [System.BitConverter]::ToString($Sha256Hasher.ComputeHash($SpkiBytes)).Replace("-", "")
        }
        $KeyBytes = $Cert.PublicKey.EncodedKeyValue.RawData
        if ($KeyBytes.Length -eq 97 -and $KeyBytes[0] -eq 0x04) {
            $SpkiBytes = New-Object byte[] 120
            [System.Array]::Copy($P384SpkiPrefix, 0, $SpkiBytes, 0, 23)
            [System.Array]::Copy($KeyBytes, 0, $SpkiBytes, 23, 97)
            return [System.BitConverter]::ToString($Sha256Hasher.ComputeHash($SpkiBytes)).Replace("-", "")
        }
    } catch {}
    return $null
}

function Test-CertBytes {
    param (
        [byte[]]$RawBytes,
        [string]$SourceFile
    )
    $Cert = $null
    try {
        $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($RawBytes)
        $script:CertificatesChecked++

        $CertSha256 = [System.BitConverter]::ToString($Sha256Hasher.ComputeHash($Cert.RawData)).Replace("-", "")
        $SpkiSha256 = Get-CertSpkiSha256 -Cert $Cert

        $FindingType      = $null
        $MatchedIndicator = $null
        $Detail           = $null

        if ($null -ne $SpkiSha256 -and $CompromisedSpkiHashes.ContainsKey($SpkiSha256)) {
            $FindingType      = "COMPROMISED_INTERMEDIATE_KEY"
            $MatchedIndicator = $SpkiSha256
            $Detail           = $CompromisedSpkiHashes[$SpkiSha256]
        }
        elseif ($CompromisedCertHashes.ContainsKey($CertSha256)) {
            $FindingType      = "COMPROMISED_INTERMEDIATE_CERT"
            $MatchedIndicator = $CertSha256
            $Detail           = $CompromisedCertHashes[$CertSha256]
        }
        elseif ($ShadowTrustRootHashes.ContainsKey($CertSha256)) {
            $FindingType      = "SHADOW_TRUST_ROOT_CA"
            $MatchedIndicator = $CertSha256
            $Detail           = $ShadowTrustRootHashes[$CertSha256]
        }

        if ($null -ne $FindingType) {
            $Findings.Add([PSCustomObject]@{
                FindingType = $FindingType
                Detail      = $Detail
                FilePath    = $SourceFile
                Subject     = $Cert.Subject
                Issuer      = $Cert.Issuer
                CertSHA256  = $CertSha256
                SpkiSHA256  = $SpkiSha256
                MatchedHash = $MatchedIndicator
                NotAfter    = $Cert.NotAfter.ToString("yyyy-MM-dd")
            })

            if ($VerboseMode -and -not $EnableSCCM) {
                $Color = if ($FindingType -like "COMPROMISED*") { "Red" } else { "Yellow" }
                Write-Host "[$FindingType] $SourceFile -> $Detail" -ForegroundColor $Color
            }
        }
    } catch {
        $ScanErrors.Add("Certificate parsing error in ${SourceFile}: $($_.Exception.Message)")
    } finally {
        if ($null -ne $Cert) { $Cert.Dispose() }
    }
}

if (-not $EnableSCCM) {
    Write-Host "`n===================================================================="
    Write-Host " eMudhra / emSign & Sectigo Shadow Trust Security Audit "
    Write-Host "===================================================================="
}

# -------------------- SCAN Audit --------------------

try {
    foreach ($Path in $SearchPaths) {

        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            if ($VerboseMode -and -not $EnableSCCM) {
                Write-Host "[SKIP] Path not present: $Path" -ForegroundColor DarkGray
            }
            continue
        }

        if ($VerboseMode -and -not $EnableSCCM) {
            Write-Host "[SCAN] Walking directory tree: $Path ..." -ForegroundColor Cyan
        }

        $PathsScanned++

        foreach ($Item in (Get-MatchingFiles -RootPath $Path)) {
            if ($Item.Length -gt 52428800) { continue }
            $FilePath = $Item.FullName
            $ScannedFiles++

            # Check Java blocked.certs / blacklisted.certs for eMudhra patch status
            if ($Item.Name -in @("blocked.certs", "blacklisted.certs")) {
                try {
                    $BlockContent = [System.IO.File]::ReadAllText($FilePath)
                    if ($BlockContent -notmatch "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493") {
                        $Findings.Add([PSCustomObject]@{
                            FindingType = "UNPATCHED_JAVA_BLOCKLIST"
                            Detail      = "Java blocked.certs missing eMudhra intermediate hashes"
                            FilePath    = $FilePath
                            Subject     = "JVM Trust Store Blocklist"
                            Issuer      = "N/A"
                            CertSHA256  = "N/A"
                            SpkiSHA256  = "N/A"
                            MatchedHash = "MISSING_EMUDHRA_BLOCK"
                            NotAfter    = "N/A"
                        })
                        if ($VerboseMode -and -not $EnableSCCM) {
                            Write-Host "[UNPATCHED_JAVA_BLOCKLIST] $FilePath" -ForegroundColor Red
                        }
                    }
                } catch {
                    $ScanErrors.Add("Unable to read Java blocklist ${FilePath}: $($_.Exception.Message)")
                }
                continue
            }

            if ($Item.Length -eq 0) { continue }

            try {
                $HasPemHeader = Select-String -LiteralPath $FilePath -Pattern '-----BEGIN CERTIFICATE-----' -SimpleMatch -Quiet -ErrorAction Stop

                if ($HasPemHeader) {
                    $Content     = [System.IO.File]::ReadAllText($FilePath)
                    $MatchesList = $PemRegex.Matches($Content)

                    foreach ($Match in $MatchesList) {
                        $Base64 = $Match.Groups[1].Value -replace '\s+', ''
                        if (-not [string]::IsNullOrWhiteSpace($Base64)) {
                            $Bytes = [Convert]::FromBase64String($Base64)
                            Test-CertBytes -RawBytes $Bytes -SourceFile $FilePath
                        }
                    }
                }
                elseif ($Item.Extension -in @('.crt', '.cer') -and $Item.Length -lt 32768) {
                    $Bytes = [System.IO.File]::ReadAllBytes($FilePath)
                    if ($Bytes.Length -gt 2 -and $Bytes[0] -eq 0x30) {
                        Test-CertBytes -RawBytes $Bytes -SourceFile $FilePath
                    }
                }
            } catch {
                $ScanErrors.Add("Unable to read ${FilePath}: $($_.Exception.Message)")
                continue
            }
        }
    }
} finally {
    if ($null -ne $Sha256Hasher) { $Sha256Hasher.Dispose() }
}

# -------------------- GET STATUS --------------------

if ($Findings.Count -gt 0) {
    $Status = "MATCH FOUND"
} elseif ($PathsScanned -eq 0) {
    $Status = "INCOMPLETE"
} else {
    $Status = "CLEAN"
}

# --------------- SCCM REPORTING ---------------------

if ($EnableSCCM) {
    $Result = [PSCustomObject]@{
        ComputerName        = $env:COMPUTERNAME
        AuditType           = "eMudhra/Sectigo Shadow Trust Audit (CVE-2026-111943)"
        AuditStatus         = $Status
        SearchPathsPresent  = $PathsScanned
        FilesScanned        = $ScannedFiles
        CertificatesChecked = $CertificatesChecked
        MatchesFound        = $Findings.Count
        ScanErrors          = $ScanErrors.Count
        MatchingCerts       = @($Findings)
        Errors              = @($ScanErrors | Select-Object -First 30)
    }
    $Result | ConvertTo-Json -Depth 5 -Compress
}
# ---------------- LOCAL REPORTING -------------------
else {
    if ($SummaryMode) {
        Write-Host "`nComputer: $env:COMPUTERNAME | Checked: $CertificatesChecked certs across $ScannedFiles files | Findings: $($Findings.Count) | Non-Fatal Access Errors: $($ScanErrors.Count) | Status: $Status"
    }
    if ($Status -eq "MATCH FOUND") {
        Write-Host "`n[MATCH FOUND] Review required:" -ForegroundColor Red
        $Findings | Format-Table FindingType, Detail, FilePath -AutoSize
    } elseif ($Status -eq "CLEAN") {
        Write-Host "`n[CLEAN] No target fingerprints found." -ForegroundColor Green
    }
}