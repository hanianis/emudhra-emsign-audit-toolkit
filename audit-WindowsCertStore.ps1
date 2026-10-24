# ============================================================
# PowerShell Certificate Audit
# Purpose: Search Windows certificate stores for eMudhra/emSign
# ============================================================

# -------------------- Config-------------------

$VerboseMode = $false #debug
$SummaryMode = $true
$EnableSCCM   = $true 

$SuspectRegex = '(?i)emSign.*G3|EM (DV|OV|EV) TLS CA - G3.*|EM OV CS CA - G3.*'

$Stores = @(
    "Cert:\LocalMachine\Root",
    "Cert:\LocalMachine\CA",
    "Cert:\LocalMachine\AuthRoot",
    "Cert:\LocalMachine\Disallowed",
    "Cert:\CurrentUser\Root",
    "Cert:\CurrentUser\CA"
)

$Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$ScanErrors = [System.Collections.Generic.List[String]]::new()
$ScannedStores = 0
$ScannedCertificates = 0

if (-not $EnableSCCM) {
    Write-Host "`n============================================"
    Write-Host " Windows Certificate Security Audit"
    Write-Host "============================================"
}

if ($VerboseMode -and -not $EnableSCCM) {
    Write-Host "[VERBOSE] Detailed logging enabled." -ForegroundColor Cyan
    Write-Host "[VERBOSE] Matching Regex Pattern: $SuspectRegex" -ForegroundColor Cyan
}

# ------- SCAN AUDIT ------------------------

foreach ($Store in $Stores) {

    if (-not (Test-Path -LiteralPath $Store -ErrorAction SilentlyContinue)) {
        $ScanErrors.Add("Store unavailable: $Store")
        if ($VerboseMode -and -not $EnableSCCM) { Write-Host "[ERROR] Store unavailable: $Store" -ForegroundColor Yellow }
        continue
    }

    try {
        $Certificates = @(Get-ChildItem -Path $Store -ErrorAction Stop)
        $ScannedStores++

        if ($VerboseMode -and -not $EnableSCCM) {
            Write-Host "`n[SCAN] Store: $Store" -ForegroundColor Cyan
            Write-Host "[VERBOSE] Certificates: $($Certificates.Count)"
        }

        foreach ($cert in $Certificates) {
            $ScannedCertificates++
            
            $IsMatch = $false
            $MatchedPattern = ""

            if ($cert.Subject -match $SuspectRegex) {
                $IsMatch = $true
                $MatchedPattern = $matches[0]
            } elseif ($cert.Issuer -match $SuspectRegex) {
                $IsMatch = $true
                $MatchedPattern = $matches[0]
            }

            if ($IsMatch) {
                try {
                    $sha256 = [System.BitConverter]::ToString(
                        $cert.GetCertHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
                    ).Replace("-", "")
                }
                catch {
                    $ScanErrors.Add("Failed to calculate SHA-256 for certificate '$($cert.Subject)': $($_.Exception.Message)")
                    $sha256 = "ERROR"
                }

                $Findings.Add([PSCustomObject]@{
                    StorePath      = $Store
                    Subject        = $cert.Subject
                    Issuer         = $cert.Issuer
                    SHA1Thumbprint = $cert.Thumbprint
                    SHA256Hash     = $sha256
                    NotAfter       = $cert.NotAfter
                    MatchedPattern = $MatchedPattern
                })

                if ($VerboseMode -and -not $EnableSCCM) {
                    Write-Host "[MATCH] $($cert.Subject)" -ForegroundColor Red
                    Write-Host "  Matched: $MatchedPattern"
                    Write-Host "  SHA-256: $sha256"
                }
            }
        }
    }
    catch {
        $ScanErrors.Add("Failed to enumerate ${Store}: $($_.Exception.Message)")
        if ($VerboseMode -and -not $EnableSCCM) { Write-Host "[ERROR] Failed to scan ${Store}: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
}

# ------------------- GET STATUS -----------------

if ($Findings.Count -gt 0) { $Status = "MATCH FOUND" }
elseif ($ScanErrors.Count -gt 0 -or $ScannedStores -lt $Stores.Count) { $Status = "INCOMPLETE" }
else { $Status = "CLEAN" }

# -------------------- SCCM REPORTING --------------

if ($EnableSCCM) {

    # Output a single structured JSON report for SCCM.
    $Result = [PSCustomObject]@{
        ComputerName        = $env:COMPUTERNAME
        AuditStatus         = $Status
        StoresExpected      = $Stores.Count
        StoresScanned       = $ScannedStores
        CertificatesChecked = $ScannedCertificates
        MatchesFound        = $Findings.Count
        ScanErrors          = $ScanErrors.Count
        MatchingCerts       = $Findings.ToArray()
        Errors              = $ScanErrors.ToArray()
    }

    $Result | ConvertTo-Json -Depth 5 -Compress
}

# -------------------- LOCAL REPORTING -----------------------
else {

    if ($SummaryMode) {
        Write-Host "`n============================================"
        Write-Host " Audit Summary"
        Write-Host "============================================"
        Write-Host "Computer:             $env:COMPUTERNAME"
        Write-Host "Stores expected:      $($Stores.Count)"
        Write-Host "Stores scanned:       $ScannedStores"
        Write-Host "Certificates checked: $ScannedCertificates"
        Write-Host "Matches found:        $($Findings.Count)"
        Write-Host "Scan errors:          $($ScanErrors.Count)"
    }

    switch ($Status) {
        "MATCH FOUND" {
            Write-Host "`n[MATCH FOUND] REVIEW REQUIRED" -ForegroundColor Red
            $Findings | Format-Table StorePath, Subject, SHA256Hash -AutoSize
        }
        "INCOMPLETE" {
            Write-Host "`n[INCOMPLETE] Audit could not verify all stores." -ForegroundColor Yellow
        }
        "CLEAN" {
            Write-Host "`n[CLEAN] No matching certificate names found in the checked stores." -ForegroundColor Green
        }
    }

    if ($ScanErrors.Count -gt 0) {
        Write-Host "`nErrors requiring attention:" -ForegroundColor Yellow
        $ScanErrors | ForEach-Object { Write-Host "  - $_" }
    }
}