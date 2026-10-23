# =========================================================================
# PowerShell Certificate Audit
# Purpose: Find affected eMudhra/Sectigo certificates in files (Shadow Trus)
# =========================================================================

# -------------------- Config --------------------------

$VerboseMode = $false #debug
$SummaryMode = $true
$EnableSCCM  = $false




	
#  all 3 Roots + 13 TLS/CS Intermediates (Native and Cross-Signed)

$TargetFingerprints = @(
	
	## emSign root CA certificates
    "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B", # emSign ECC Root CA - G3
    "7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D", # emSign Root TLS CA - G3 
    "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5",  # emSign Root CS CA - G3

	## Intermediate TLS certificates — G3B and G3C 
    "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493", # Native eMudhra G3B Domain Validation (DV) TLS intermediate
    "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE", # Sectigo cross-signed G3B DV TLS intermediate
    "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B", # Native eMudhra G3B Organization Validation (OV) TLS intermediate
    "5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699", # Sectigo cross-signed G3B OV TLS intermediate
    "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838", # Native eMudhra G3B Extended Validation (EV) TLS intermediate
    "579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512", # Sectigo cross-signed G3B EV TLS intermediate
    "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19", # Native eMudhra G3C DV TLS intermediate
    "62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72", # Sectigo cross-signed G3C DV TLS intermediate
    "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F",   # Native eMudhra G3C OV TLS intermediate
    "7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489", # Sectigo cross-signed G3C OV TLS intermediate
    "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3", # Native eMudhra G3C EV TLS intermediate
    "FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F", # Sectigo cross-signed G3C EV TLS intermediate

	## Code Signing certificates — G3B and G3C 
    "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4", # Native eMudhra G3B OV Code Signing intermediate
    "A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8", # Sectigo cross-signed G3B OV Code Signing intermediate
    "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1", # Native eMudhra G3C OV Code Signing intermediate 
    "84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"  # Sectigo cross-signed G3C OV Code Signing intermediate
)

# CONFIRMED COMPROMISED INTERMEDIATE CA PUBLIC KEYS

   # TLS — Domain Validation (DV)
    # "EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105", # EM DV TLS CA - G3B
    # "49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F", # EM DV TLS CA - G3C

  # TLS — Extended Validation (EV)
    # "E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41", # EM EV TLS CA - G3B
    # "5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0", # EM EV TLS CA - G3C

  # TLS — Organization Validation (OV)
    # "43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B", # EM OV TLS CA - G3B
    # "63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8", # EM OV TLS CA - G3C

  # Code Signing — Organization Validation (OV CS)
    # "EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6", # EM OV CS CA - G3B
    # "92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30"  # EM OV CS CA - G3C


$SearchPaths = @(
    "C:\Program Files (x86)",
    "C:\Program Files",
    "C:\ProgramData",
    "C:\Users",
    "C:\tools",
    "C:\inetpub"
)

$Extensions = @("*.pem", "*.crt", "*.bundle", "*ca-bundle*", "*cacert*")

$Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$ScanErrors = [System.Collections.Generic.List[String]]::new()
$ScannedFiles = 0
$CertificatesChecked = 0
$PathsScanned = 0

if (-not $EnableSCCM) {
    Write-Host "`n=================================================================="
    Write-Host " eMudhra/Sectigo Certificate Security Audit Shadow Trust "
    Write-Host "===================================================================="
}

if ($VerboseMode -and -not $EnableSCCM) {
    Write-Host "[VERBOSE] Detailed logging enabled." -ForegroundColor Cyan
}

# -------------------- SCAN Audit --------------------

foreach ($Path in $SearchPaths) {

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        $ScanErrors.Add("Search path unavailable: $Path")
        if ($VerboseMode -and -not $EnableSCCM) { Write-Host "[ERROR] Search path unavailable: $Path" -ForegroundColor Yellow }
        continue
    }

    $PathsScanned++
    $EnumerationErrors = @()

    $Files = @(Get-ChildItem -LiteralPath $Path -Include $Extensions -File -Recurse -ErrorAction SilentlyContinue -ErrorVariable +EnumerationErrors)
    foreach ($err in $EnumerationErrors) { $ScanErrors.Add("Enumeration error under ${Path}: $($err.Exception.Message)") }

    foreach ($Item in $Files) {
        $FilePath = $Item.FullName
        $ScannedFiles++

        try {
            $Content = Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop
        } catch {
            $ScanErrors.Add("Unable to read ${FilePath}: $($_.Exception.Message)")
            continue
        }

        if (-not ($Content -match '-----BEGIN CERTIFICATE-----')) { continue }

        $Blocks = [regex]::Matches($Content, '(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----')

        foreach ($Block in $Blocks) {
            $Cert = $null
            try {
                $Base64 = $Block.Value -replace '-----BEGIN CERTIFICATE-----', '' -replace '-----END CERTIFICATE-----', '' -replace '\s', ''
                $Bytes = [Convert]::FromBase64String($Base64)
                $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Bytes)
                
                $CertificatesChecked++
                
                $Hash = [System.BitConverter]::ToString($Cert.GetCertHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)).Replace("-", "")

                if ($TargetFingerprints -contains $Hash) {
                    $Findings.Add([PSCustomObject]@{
                        FilePath       = $FilePath
                        Subject        = $Cert.Subject
                        Issuer         = $Cert.Issuer
                        SHA1Thumbprint = $Cert.Thumbprint
                        SHA256Hash     = $Hash
                        NotAfter       = $Cert.NotAfter
                    })

                    if ($VerboseMode -and -not $EnableSCCM) {
                        Write-Host "[MATCH] $FilePath - $($Cert.Subject)" -ForegroundColor Red
                    }
                }
            } catch {
                $ScanErrors.Add("Certificate parsing error in ${FilePath}: $($_.Exception.Message)")
            } finally {
                if ($null -ne $Cert) { $Cert.Dispose() }
            }
        }
    }
}

# -------------------- GET STATUS -----------------

if ($Findings.Count -gt 0) { $Status = "MATCH FOUND" }
elseif ($ScanErrors.Count -gt 0 -or $PathsScanned -lt $SearchPaths.Count) { $Status = "INCOMPLETE" }
else { $Status = "CLEAN" }

# --------------- SCCM REPORTING ---------------------

if ($EnableSCCM) {
    $Result = [PSCustomObject]@{
        ComputerName        = $env:COMPUTERNAME
        AuditType           = "eMudhra/Sectigo Shadow Trust Audit"
        AuditStatus         = $Status
        SearchPathsExpected = $SearchPaths.Count
        SearchPathsScanned  = $PathsScanned
        FilesScanned        = $ScannedFiles
        CertificatesChecked = $CertificatesChecked
        MatchesFound        = $Findings.Count
        ScanErrors          = $ScanErrors.Count
        MatchingCerts       = $Findings.ToArray()
        Errors              = $ScanErrors.ToArray()
    }
    $Result | ConvertTo-Json -Depth 5 -Compress
}
# ---------------- LOCAL REPORTING ----------------------
else {
    if ($SummaryMode) {
        Write-Host "`nComputer: $env:COMPUTERNAME | Checked: $CertificatesChecked certs across $ScannedFiles files | Status: $Status"
    }
    if ($Status -eq "MATCH FOUND") {
        Write-Host "`n[MATCH FOUND] Review required." -ForegroundColor Red
        $Findings | Format-Table FilePath, Subject, SHA256Hash -AutoSize
    } elseif ($Status -eq "CLEAN") {
        Write-Host "`n[CLEAN] No target fingerprints found." -ForegroundColor Green
    }
}