#!/bin/bash
#
# Generate DKIM keys for ApexMail
#
# Usage: ./generate-dkim.sh <domain> <selector>
# Example: ./generate-dkim.sh apexmail.ee apexmail2026

set -e

DOMAIN=${1:-apexmail.ee}
SELECTOR=${2:-apexmail2026}
KEY_DIR="./config/dkim"

echo "Generating DKIM keys for domain: $DOMAIN, selector: $SELECTOR"

# Create directory if it doesn't exist
mkdir -p "$KEY_DIR"

# Generate private key (RSA 2048-bit)
openssl genrsa -out "$KEY_DIR/private.pem" 2048

# Generate public key
openssl rsa -in "$KEY_DIR/private.pem" -pubout -out "$KEY_DIR/public.pem"

# Extract public key in DNS format (remove headers and newlines)
PUBLIC_KEY=$(grep -v "^-" "$KEY_DIR/public.pem" | tr -d '\n')

# Create DNS record file
cat > "$KEY_DIR/dns-record.txt" << EOF
=============================================================================
DKIM DNS Record for $DOMAIN
=============================================================================

Add this TXT record to your DNS:

Host:  ${SELECTOR}._domainkey.${DOMAIN}
Type:  TXT
Value: v=DKIM1; k=rsa; p=${PUBLIC_KEY}

If the record is too long for your DNS provider, you may need to split it:

"v=DKIM1; k=rsa; p=" "${PUBLIC_KEY:0:255}" "${PUBLIC_KEY:255}"

=============================================================================
SPF Record (recommended)
=============================================================================

Host:  ${DOMAIN}
Type:  TXT
Value: v=spf1 ip4:YOUR_SERVER_IP -all

=============================================================================
DMARC Record (recommended)
=============================================================================

Host:  _dmarc.${DOMAIN}
Type:  TXT
Value: v=DMARC1; p=quarantine; rua=mailto:dmarc@${DOMAIN}; pct=100

=============================================================================
EOF

echo ""
echo "DKIM keys generated successfully!"
echo ""
echo "Files created:"
echo "  - $KEY_DIR/private.pem (KEEP THIS SECRET!)"
echo "  - $KEY_DIR/public.pem"
echo "  - $KEY_DIR/dns-record.txt"
echo ""
echo "Next steps:"
echo "1. Add the DNS records from $KEY_DIR/dns-record.txt to your DNS"
echo "2. Wait for DNS propagation (can take up to 48 hours)"
echo "3. Verify with: dig TXT ${SELECTOR}._domainkey.${DOMAIN}"
echo ""

# Set secure permissions
chmod 600 "$KEY_DIR/private.pem"
chmod 644 "$KEY_DIR/public.pem"
chmod 644 "$KEY_DIR/dns-record.txt"

echo "Private key permissions set to 600 (owner read/write only)"
