#!/usr/bin/env python3
"""
Q5: Tampering Detection using DNSSEC

Demonstrates how DNSSEC detects tampered DNS records.
Uses the local SEED Lab DNS server and custom validator.
"""

import sys
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.name
import dns.dnssec
import dns.flags

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
LOCAL_DNS    = "10.9.0.53"   # Local DNS server
AUTH_SERVER  = "10.9.0.65"   # example.edu authoritative server
DOMAIN       = "www.example.edu"
RECORD_TYPE  = "A"


# ─────────────────────────────────────────────
# Query a specific DNS server
# ─────────────────────────────────────────────

def query_server(domain, record_type, server, want_dnssec=True):
    """Send DNS query to a specific server and return response."""
    try:
        request = dns.message.make_query(
            domain, record_type, want_dnssec=want_dnssec)
        response = dns.query.udp(request, server, timeout=5)
        return response
    except Exception as e:
        print(f"  [-] Query failed: {e}")
        return None


# ─────────────────────────────────────────────
# Extract A record IP from response
# ─────────────────────────────────────────────

def extract_ip(response):
    """Extract IP address from DNS response."""
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for rdata in rrset:
                return str(rdata), rrset
    return None, None


# ─────────────────────────────────────────────
# Extract RRSIG from response
# ─────────────────────────────────────────────

def extract_rrsig(response):
    """Extract RRSIG rrset from DNS response."""
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            return rrset
    return None


# ─────────────────────────────────────────────
# Get DNSKEY from authoritative server
# ─────────────────────────────────────────────

def get_dnskey_local(zone, server):
    """Fetch DNSKEY records from local authoritative server."""
    try:
        request = dns.message.make_query(
            zone, "DNSKEY", want_dnssec=True)
        response = dns.query.udp(request, server, timeout=5)
        keys = {}
        zone_name = dns.name.from_text(zone)
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                keys[zone_name] = rrset
                return keys, rrset
        return None, None
    except Exception as e:
        print(f"  [-] DNSKEY fetch failed: {e}")
        return None, None


# ─────────────────────────────────────────────
# Custom DNSSEC Validator
# ─────────────────────────────────────────────

def validate_record(domain, record_type, server):
    """
    Validate a DNS record using DNSSEC.
    Fetches the record + RRSIG from server,
    fetches DNSKEY, and verifies the signature.
    Returns (ip, valid, failure_reason)
    """
    # Get the record with DNSSEC
    response = query_server(domain, record_type, server)
    if not response:
        return None, False, "Query failed"

    # Extract IP and answer rrset
    ip, answer_rrset = extract_ip(response)
    if not ip:
        return None, False, "No A record in response"

    # Extract RRSIG
    rrsig_rrset = extract_rrsig(response)
    if not rrsig_rrset:
        return ip, False, "No RRSIG in response"

    # Get signer zone from RRSIG
    signer = None
    for rdata in rrsig_rrset:
        signer = str(rdata.signer).rstrip('.')
        key_tag = rdata.key_tag
        break

    print(f"  [*] RRSIG signer: {signer}, key_tag: {key_tag}")

    # Get DNSKEY from authoritative server
    keys, dnskey_rrset = get_dnskey_local(signer, server)
    if not keys:
        return ip, False, "Could not retrieve DNSKEY"

    print(f"  [*] DNSKEY retrieved for {signer}")

    # Verify RRSIG using DNSKEY
    # Check AD flag in response
    ad_flag = bool(response.flags & dns.flags.AD)

    # Verify RRSIG using DNSKEY
    try:
        dns.dnssec.validate(answer_rrset, rrsig_rrset, keys)
        return ip, True, None, ad_flag
    except dns.dnssec.ValidationFailure as e:
        return ip, False, f"RRSIG verification failed: {e}", ad_flag
    except Exception as e:
        return ip, False, f"Validation error: {e}", ad_flag


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Q5: DNSSEC Tampering Detection")
    print(f"  Domain : {DOMAIN}")
    print(f"  Record : {RECORD_TYPE}")
    print("=" * 60)

    # ── Part A: Query BEFORE tampering (use original IP) ──
    print(f"\n[Part A] Querying authoritative server: {AUTH_SERVER}")
    print(f"[*] Validating {DOMAIN} {RECORD_TYPE}...")

    ip, valid, reason, ad_flag = validate_record(
        DOMAIN, RECORD_TYPE, AUTH_SERVER)

    print(f"\n  IP returned  : {ip}")
    print(f"  AD flag      : {'SET (authentic data)' if ad_flag else 'NOT SET (unauthenticated)'}")
    if valid:
        print(f"  Validation   : VALID")
    else:
        print(f"  Validation   : INVALID")
        print(f"  Failure point: {reason}")

    print()

    # ── Part B: Analysis ──
    print("=" * 60)
    print("  DNSSEC Validation Result")
    print("=" * 60)
    print(f"  Domain           : {DOMAIN}")
    print(f"  Record           : {RECORD_TYPE}")
    print(f"  IP returned      : {ip}")

    if valid:
        status = "VALID"
        print(f"  Validation       : {status}")
        print(f"  Failure Reason   : None")
    else:
        status = "INVALID"
        print(f"  Validation       : {status}")
        print(f"  Failure Reason   : {reason}")
        print()
        print("  Failure Analysis:")
        if "RRSIG verification failed" in str(reason):
            print("  - RRSIG verification FAILED for A record")
            print("  - Signature does not match returned IP")
            print("  - Record was modified after signing")
            print("  - DNSSEC successfully detected tampering")

    print("=" * 60)


if __name__ == "__main__":
    main()