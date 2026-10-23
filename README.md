# eMudhra / Sectigo Certificate Security Audit

A cross-platform auditing toolkit for identifying certificates associated with the eMudhra intermediate Certificate Authority (CA) private-key compromise.

This repository provides Linux and Windows auditing scripts to inspect operating-system trust stores, application certificate bundles, and Java KeyStores. It supports local investigations and enterprise-scale auditing through Microsoft Configuration Manager (SCCM/MECM).

> **Security notice:** These scripts are intended for detection and investigation. A certificate match does not, by itself, prove that a system was compromised or that a certificate was used maliciously.

## Table of Contents

- [Overview](#overview)
- [Confirmed Compromised Public Keys](#confirmed-compromised-public-keys)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Linux Audit](#1-linux-audit)
- [Windows Certificate Store Audit](#2-windows-certificate-store-audit)
- [Windows Shadow Trust Audit](#3-windows-shadow-trust-audit)
- [SCCM/MECM Deployment](#sccmmecm-deployment)
- [Reports and Output](#reports-and-output)
- [Incident Response and Remediation](#incident-response-and-remediation)
- [Limitations](#limitations)
- [References](#references)

## Overview

The toolkit covers three complementary audit areas.

| Script | Platform | Scope |
|---|---|---|
| `audit-emudhra-linux.sh` | Linux | System trust stores, filesystem certificate bundles, and Java KeyStores |
| `Audit-WindowsCertStore.ps1` | Windows | Windows CryptoAPI certificate stores |
| `Audit-WindowsShadowTrust.ps1` | Windows | Certificate bundles stored in application and runtime directories |

The objective is to identify affected public keys and certificate indicators, record their locations, and provide evidence for security teams to investigate and remediate.

## Confirmed Compromised Public Keys

The incident involved eight intermediate CA public keys associated with insufficient randomness during key generation.

The following are the eight confirmed **SPKI SHA-256 fingerprints** to use when detecting certificates containing these public keys.

### Confirmed indicator list

| # | Intermediate CA | Purpose | SPKI SHA-256 |
|---:|---|---|---|
| 1 | EM DV TLS CA - G3B | TLS | `EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105` |
| 2 | EM DV TLS CA - G3C | TLS | `49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F` |
| 3 | EM EV TLS CA - G3B | TLS | `E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41` |
| 4 | EM EV TLS CA - G3C | TLS | `5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0` |
| 5 | EM OV TLS CA - G3B | TLS | `43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B` |
| 6 | EM OV TLS CA - G3C | TLS | `63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8` |
| 7 | EM OV CS CA - G3B | Code signing | `EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6` |
| 8 | EM OV CS CA - G3C | Code signing | `92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30` |

### Indicator maintenance requirements

**Before deploying the audit scripts, review their existing fingerprint lists.**

1. Remove or comment out previous, unverified, or unrelated fingerprints from the *confirmed compromised SPKI* list.
2. Retain the eight indicators above as the confirmed compromised-public-key indicators.
3. Keep any additional certificate fingerprints or investigation indicators in a separate list, clearly labeled according to their verified role.
4. Do not classify a fingerprint as confirmed solely because it contains an eMudhra or Sectigo-related name.
5. Validate the indicator list against the authoritative incident advisory before production deployment.

These eight values are SPKI fingerprints, not full X.509 certificate fingerprints. An SPKI hash identifies the public key, whereas a certificate fingerprint hashes the entire encoded certificate. Different certificates, including cross-signed certificates, can contain the same public key but have different certificate fingerprints.

### Recommended indicator configuration

Use a dedicated list in each script, or maintain a common indicator file if your scripts support importing one.

```text
# Confirmed compromised intermediate CA public keys
# Fingerprint type: SPKI SHA-256

EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105
49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F
E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41
5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0
43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B
63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8
EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6
92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30
```

The configuration above is an indicator reference. Each script must calculate the certificate's SPKI SHA-256 correctly before comparing it with this list.

## Repository Structure

```text
.
├── audit-emudhra-linux.sh
├── Audit-WindowsCertStore.ps1
├── Audit-WindowsShadowTrust.ps1
├── README.md
└── audit-reports-eMudhra/
    └── generated reports
```

The report directory is generated during Linux audit execution. It is not necessary to commit generated reports to GitHub.

Recommended `.gitignore` entries:

```gitignore
audit-reports-eMudhra/
*.log
*.csv
*.json
```

Adjust these exclusions if your project intentionally version-controls sanitized test results.

## Prerequisites

### Linux

- Bash 4.0 or later
- `openssl`
- `grep`
- `find`
- `awk`
- Optional: `keytool` for Java KeyStore inspection

### Windows

- Windows PowerShell 5.1 or a compatible version supported by the scripts
- Administrator privileges for comprehensive local inspection
- Access to the directories and certificate stores under audit
- SCCM/MECM permissions for enterprise deployment

Verify the actual requirements and supported versions against the script implementations before production deployment.

## 1. Linux Audit

**Script:** `audit-emudhra-linux.sh`

The Linux script audits the operating-system trust store and scans designated filesystem trees for standalone certificate files and Java KeyStores.

### Execution

1. Grant execution permissions:

   ```bash
   chmod +x audit-emudhra-linux.sh
   ```

2. Execute with root privileges:

   ```bash
   sudo ./audit-emudhra-linux.sh
   ```

3. Review the generated report:

   ```text
   ./audit-reports-eMudhra/
   ```

Root privileges are recommended to inspect protected system directories, application installations, and user profiles.

### Java KeyStore inspection

If Java KeyStores are in scope, verify that `keytool` is installed:

```bash
keytool -help
```

The script must explicitly support binary Java KeyStores for them to be inspected. The presence of `keytool` alone does not guarantee that every Java truststore is discovered.

### Recommended Linux audit targets

Depending on the environment, review:

- `/etc/ssl/`
- `/etc/pki/`
- `/usr/local/share/ca-certificates/`
- `/opt/`
- Application-specific directories
- Java runtime installations
- Python environments and `certifi` bundles
- Custom TLS trust configurations

The actual coverage depends on the paths configured in the script.

## 2. Windows Certificate Store Audit

**Script:** `Audit-WindowsCertStore.ps1`

The Windows certificate-store script audits selected local Windows CryptoAPI certificate stores, including:

- `Root`
- `CA`
- `AuthRoot`
- `Disallowed`
- `CurrentUser`

It uses configured Subject and Issuer patterns to identify certificates requiring further investigation.

### Running locally

1. Open PowerShell as **Administrator**.
2. Configure the reporting flags at the beginning of the script:

   ```powershell
   $EnableSCCM  = $false
   $VerboseMode = $true
   $SummaryMode = $true
   ```

3. Execute the script:

   ```powershell
   powershell.exe -ExecutionPolicy Bypass `
       -File .\Audit-WindowsCertStore.ps1
   ```

4. Review the output and investigate any matches.

The flags above assume that the script implements the corresponding local-output behavior. Check its configuration and output destination before execution.

### Running through SCCM/MECM

1. Open `Audit-WindowsCertStore.ps1`.
2. Enable SCCM output:

   ```powershell
   $EnableSCCM = $true
   ```

3. In the Configuration Manager console, navigate to **Software Library → Scripts**.
4. Create a new PowerShell script and paste the complete script contents.
5. Approve the script according to your organization's governance process.
6. Run it against an appropriate device collection.
7. Review the execution results and emitted JSON payload.

The SCCM mode is intended to provide structured output that can be captured by the Configuration Manager script execution results dashboard.

## 3. Windows Shadow Trust Audit

**Script:** `Audit-WindowsShadowTrust.ps1`

The shadow-trust script recursively scans designated filesystem paths for certificate bundles that may be consumed directly by applications instead of relying on the Windows CryptoAPI certificate stores.

Examples include:

- `.pem`
- `.crt`
- `.bundle`
- `ca-bundle`
- `cacert`

Coverage depends on the extensions and file-discovery logic implemented by the script.

### Configuring scan targets

Edit the `$SearchPaths` array near the beginning of the script:

```powershell
$SearchPaths = @(
    "C:\Program Files (x86)",
    "C:\Program Files",
    "C:\ProgramData",
    "C:\Users",
    "C:\tools",
    "C:\inetpub"
    # "D:\Applications",
    # "E:\Data"
)
```

Add other directories or drive locations relevant to your environment.

**Performance consideration:** Avoid scanning large backup repositories, storage volumes, and data-only directories unnecessarily. Begin with application, runtime, and development directories, then expand the scope based on findings.

### Running locally

1. Open an elevated PowerShell terminal.
2. Configure the reporting flags:

   ```powershell
   $EnableSCCM  = $false
   $SummaryMode = $true
   ```

3. Execute:

   ```powershell
   powershell.exe -ExecutionPolicy Bypass `
       -File .\Audit-WindowsShadowTrust.ps1
   ```

4. Review the summary and any detected certificates.

### Running through SCCM/MECM

1. Enable structured output:

   ```powershell
   $EnableSCCM = $true
   ```

2. Import and approve the script through Configuration Manager.
3. Deploy it to the relevant device collection.
4. Review the JSON output and identify affected hosts and certificate locations.

### Example JSON output

The following is an illustrative example of a certificate detection:

```json
{
  "ComputerName": "WS-SEC-01",
  "AuditType": "eMudhra/Sectigo Shadow Trust Audit",
  "AuditStatus": "MATCH FOUND",
  "FilesScanned": 1420,
  "CertificatesChecked": 3120,
  "MatchesFound": 1,
  "MatchingCerts": [
    {
      "FilePath": "C:\\tools\\python311\\Lib\\site-packages\\certifi\\cacert.pem",
      "Subject": "CN=emSign ECC Root CA - G3, O=eMudhra Technologies Limited, C=IN",
      "SHA256Hash": "<verified SHA-256 value>"
    }
  ]
}
```

This example illustrates the reporting structure. The values are not a verified live detection.

**Important:** Do not substitute a root certificate fingerprint for one of the eight compromised intermediate SPKI fingerprints. Ensure that the script reports the fingerprint type explicitly, for example `CertificateSHA256` or `SPKISHA256`.

## SCCM/MECM Deployment

For enterprise-wide auditing, deploy the Windows certificate-store and filesystem scripts separately so their results can be interpreted according to their audit scope.

Recommended deployment sequence:

1. Validate each script on a representative test system.
2. Confirm the fingerprint list, permissions, runtime, and output format.
3. Deploy to a pilot device collection.
4. Review matches and false positives.
5. Expand deployment to server and workstation collections in controlled phases.
6. Consolidate findings for incident-response tracking.
7. Rerun the audits after remediation.

Use appropriate maintenance windows when scanning large filesystems. Apply least-privilege access and follow internal change-management procedures.

## Reports and Output

Depending on the script, reports may include:

- Hostname and audit status
- Certificate Subject and Issuer
- Full certificate SHA-256 fingerprint
- SPKI SHA-256 fingerprint
- Certificate file location
- Files and certificates scanned
- Number of detected matches
- JSON output for enterprise collection

Keep the fingerprint type explicit in every report. Do not label an SPKI fingerprint as a certificate fingerprint or vice versa.

Store reports in an access-controlled location. They may contain internal hostnames, usernames, filesystem paths, and other sensitive operational details.

## Incident Response and Remediation

If a certificate matches one of the confirmed indicators:

1. **Validate the match.** Recalculate the SPKI SHA-256 fingerprint and compare it against the confirmed list.
2. **Identify dependencies.** Determine which applications, services, or trust stores use the certificate.
3. **Assess trust.** Establish whether the certificate is trusted by the OS, an application, a browser, or a custom trust store.
4. **Investigate activity.** Review relevant TLS, proxy, endpoint, and code-signing telemetry.
5. **Follow official guidance.** Apply the CA or vendor's recommended distrust, revocation, and replacement actions.
6. **Replace affected certificates.** Where necessary, reissue certificates through an unaffected and trusted hierarchy.
7. **Retest.** Rerun the audit and verify the replacement certificate chains.
8. **Preserve evidence.** Retain original findings, investigation notes, and remediation records.

Do not automatically delete certificates solely because their Subject or Issuer matches a search pattern. Validate the certificate and its role before making trust-store changes.

A matching public key is a serious indicator because the corresponding private key may be recoverable. However, the match alone does not establish malicious use or prove that the host is compromised.

## Limitations

- Filesystem audits only cover configured paths and supported file formats.
- Windows CryptoAPI auditing does not automatically cover every application-specific trust store.
- Java KeyStores and proprietary application stores may require separate inspection.
- Subject and Issuer matching can generate false positives and may miss certificates whose metadata differs.
- SPKI SHA-256 and full X.509 certificate SHA-256 fingerprints are different indicators.
- A clean report does not prove that every certificate or trust store on a system has been examined.
- The effectiveness of the audit depends on the script implementation, the accuracy of its indicators, and the completeness of its scan paths.
- Detection does not establish that a certificate was used maliciously or that a system is compromised.

Use these scripts as one component of a broader certificate incident-response process, alongside authoritative advisories, certificate-chain validation, application inventory, and centralized security monitoring.

## References

- [Kudelski Security — eMudhra Intermediate CA Private Key Compromise](https://kudelskisecurity.com/research/emudhra-intermediate-ca-private-key-compromise)
- [Google Security Blog — Protecting Chrome and Android Users from Compromised eMudhra Intermediate CA Certificates](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)

Consult the authoritative advisories for current mitigation instructions and any changes to the affected certificate list.

---

**Disclaimer:** This repository is provided for defensive security auditing and incident-response support. Validate findings before remediation and test scripts in a controlled environment before deploying them to production systems.
