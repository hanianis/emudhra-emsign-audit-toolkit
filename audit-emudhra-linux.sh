#!/usr/bin/env bash
# ==============================================================================
# Linux System & Application Trust Store Audit (eMudhra / emSign & Sectigo)
# ==============================================================================

set -u

# ----------------- conf -----------------
REPORT_DIR="./audit-reports-eMudhra"
HOST="$(hostname)"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/audit_${HOST}_${TIMESTAMP}.md"

exec > >(tee -a "$REPORT_FILE") 2>&1

# Counters for final summary
SYS_BUNDLES_SCANNED=0
SHADOW_BUNDLES_SCANNED=0
CERTS_CHECKED=0
MATCHES_FOUND=0

#Confirmed Compromised Public Keys

TARGET_HASHES_REGEX="^(EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105|49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F|E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41|5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0|43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B|63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8|EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6|92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30)$"

#NON-Confirmed Compromised Public Keys

#TARGET_HASHES_REGEX="^(86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B|7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D|F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5|D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4|42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493|45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE|98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B|5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699|E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838|579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512|0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19|62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72|CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F|7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489|432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3|FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F|9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4|A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8|4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1|84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD)$"



SUSPECT_CN_REGEX="emSign.*G3|AAA Certificate Services|EM (DV|OV|EV) TLS CA - G3|EM OV CS CA - G3"

# ----------------- helper function -----------------
scan_pem_file() {
    local file="$1"
    local label="$2"
    local cert=""
    local in_cert=0
    local line output fp subj

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == *"-----BEGIN "* && "$line" == *"CERTIFICATE-----"* ]]; then
            in_cert=1
            cert="$line"$'\n'
        elif [[ "$line" == *"-----END "* && "$line" == *"CERTIFICATE-----"* && $in_cert -eq 1 ]]; then
            cert+="$line"$'\n'
            in_cert=0
            ((CERTS_CHECKED++))

            output=$(openssl x509 -noout -fingerprint -sha256 -subject <<< "$cert" 2>/dev/null)
            if [[ -n "$output" ]]; then
			
                fp="${output%%$'\n'*}"
                fp="${fp#*=}"
                fp="${fp//:/}"
                subj="${output#*$'\n'}"

                if [[ "$fp" =~ $TARGET_HASHES_REGEX ]]; then
                    echo "  [!] MATCH IN ${label}: ${file}"
                    echo "      ${subj} | SHA256: ${fp}"
                    ((MATCHES_FOUND++))
                fi
            fi
        elif [[ $in_cert -eq 1 ]]; then
            cert+="$line"$'\n'
        fi
    done < "$file"
}

# ----------------- header -----------------
cat <<EOF
# System Certificate Trust Audit
========================================
  Hostname       : $HOST
  Current User   : $(whoami)
  User ID        : $(id -u)
  Groups         : $(id -Gn)
  Distribution   : $(source /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-Unknown}" || echo "Unknown")
  Kernel         : $(uname -r)
  Architecture   : $(uname -m)
  IP Addresses   : $(ip -o -4 addr show up scope global 2>/dev/null | awk '{split($4,a,"/"); printf "%s ",a[1]}')
  Audit Date     : $(date '+%Y-%m-%d %H:%M:%S %Z')
========================================
EOF

echo ""
echo "=== [1] Auditing System Trust Store ==="

SYS_BUNDLES=(
    "/etc/ssl/certs/ca-certificates.crt"                # Debian/Ubuntu/Gentoo/Alpine
    "/etc/pki/tls/certs/ca-bundle.crt"                  # RHEL/CentOS/Rocky/Fedora
    "/var/lib/ca-certificates/ca-bundle.pem"            # SUSE/openSUSE
    "/etc/ssl/cert.pem"                                 # Alpine/macOS/FreeBSD fallback
)

for bundle in "${SYS_BUNDLES[@]}"; do
    if [[ -f "$bundle" ]]; then
        echo "[*] Scanning system bundle: $bundle"
        ((SYS_BUNDLES_SCANNED++))
        scan_pem_file "$bundle" "SYSTEM TRUST"
    fi
done

if command -v trust >/dev/null 2>&1; then
    echo "[*] Checking p11-kit blocklist status:"
    blocklisted=$(trust list --filter=blocklist 2>/dev/null | grep -E -i "emSign|AAA Certificate Services|EM .* CA - G3" || true)
    if [[ -n "$blocklisted" ]]; then
        echo "  [+] Active p11-kit blocklist entries found:"
        echo "$blocklisted" | sed 's/^/      /'
    else
        echo "  [-] No eMudhra/AAA entries found in p11-kit blocklist."
    fi
fi

echo ""
echo "=== [2] Hunting Shadow Trust Stores (Python, Node, Go, Java, Conda, VenVs, curl) ==="

while IFS= read -r -d '' file; do
    [[ -L "$file" ]] && continue

    # Case A: Standard PEM bundle
    if grep -q "BEGIN .*CERTIFICATE" "$file" 2>/dev/null; then
	
        ((SHADOW_BUNDLES_SCANNED++))
        if openssl crl2pkcs7 -nocrl -certfile "$file" 2>/dev/null | openssl pkcs7 -print_certs -noout 2>/dev/null | grep -Eqi "$SUSPECT_CN_REGEX"; then
            scan_pem_file "$file" "SHADOW PEM BUNDLE"
        fi

    # Case B: Binary Java Keystore (cacerts in JKS / PKCS12 format)
    elif [[ "$(basename "$file")" == "cacerts" ]] && command -v keytool >/dev/null 2>&1; then
        ((SHADOW_BUNDLES_SCANNED++))
        java_out=$(keytool -list -v -keystore "$file" -storepass changeit 2>/dev/null || true)
        if [[ -n "$java_out" ]]; then
            while IFS= read -r match_hash; do
                [[ -z "$match_hash" ]] && continue
                echo "  [!] MATCH IN JAVA CACERTS: $file | SHA256: $match_hash"
                ((MATCHES_FOUND++))
            done < <(echo "$java_out" | awk '/SHA256:/{gsub(":","",$2); print $2}' | grep -E "$TARGET_HASHES_REGEX" || true)
        fi
    fi
done < <(find /opt /var /home /usr /srv /etc -type f \( -name "cacert.pem" -o -name "cacerts.pem" -o -name "ca-bundle.crt" -o -name "certs.pem" -o -name "cert.pem" -o -name "cacerts" \) -print0 2>/dev/null)

# ----------------- summary -----------------
if [[ $MATCHES_FOUND -gt 0 ]]; then
    STATUS="MATCH FOUND (ACTION REQUIRED)"
else
    STATUS="CLEAN"
fi

cat <<EOF

========================================
# Audit Summary
  Status                 : $STATUS
  System Bundles Scanned : $SYS_BUNDLES_SCANNED
  Shadow Stores Scanned  : $SHADOW_BUNDLES_SCANNED
  PEM Certs Evaluated    : $CERTS_CHECKED
  Total Matches Found    : $MATCHES_FOUND
  Report Saved To        : $REPORT_FILE
========================================
EOF