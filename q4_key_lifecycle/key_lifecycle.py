#!/usr/bin/env python3
"""
Q4: DNSSEC Key Lifecycle Analyzer

Analyzes real-world DNSSEC key lifecycle by detecting:
- Multiple keys (KSK/ZSK)
- Old/new key coexistence (rollover in progress)
- DS mismatches between parent and child zone
"""

import sys
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.name
import dns.dnssec
import dns.flags
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# Import Q1 validation module
# ─────────────────────────────────────────────
sys.path.append('../q1_validation_module')
from dnssec_validator import (
    get_dnskey,
    get_rrsig,
    get_ds_from_parent,
    verify_rrsig,
    verify_dnskey_with_ds
)

RESOLVER_IP = "8.8.8.8"


# ─────────────────────────────────────────────
# STEP 1: Retrieve all DNSKEY records with details
# ─────────────────────────────────────────────

def retrieve_dnskeys(domain):
    """
    Retrieve all DNSKEY records for the domain.
    Categorizes each key as KSK or ZSK and extracts:
    - key_tag, algorithm, flags, key size indicator
    Returns (key_list, ksks, zsks, keys, dnskey_answer) tuple.
    """
    print(f"\n[*] Retrieving DNSKEY records for {domain}...")
    keys, dnskey_answer = get_dnskey(domain)
    if not dnskey_answer:
        print(f"[-] No DNSKEY records found for {domain}")
        return [], None, None

    key_list = []
    ksks = []
    zsks = []

    for rdata in dnskey_answer:
        key_tag = dns.dnssec.key_id(rdata)
        key_type = "KSK" if rdata.flags == 257 else "ZSK"
        key_info = {
            "key_tag": key_tag,
            "algorithm": rdata.algorithm,
            "flags": rdata.flags,
            "type": key_type,
            "rdata": rdata
        }
        key_list.append(key_info)

        if key_type == "KSK":
            ksks.append(key_info)
        else:
            zsks.append(key_info)

        print(f"  [{key_type}] key_tag={key_tag} "
              f"algorithm={rdata.algorithm} "
              f"flags={rdata.flags}")

    print(f"\n  Summary: {len(ksks)} KSK(s), {len(zsks)} ZSK(s) found")
    return key_list, ksks, zsks, keys, dnskey_answer


# ─────────────────────────────────────────────
# STEP 2: Retrieve RRSIG records with expiry info
# ─────────────────────────────────────────────

def retrieve_rrsigs(domain, record_type="DNSKEY"):
    """
    Retrieve RRSIG records for the domain and record type.
    Extracts signature validity period and key_tag used.
    Returns list of RRSIG detail dicts.
    """
    print(f"\n[*] Retrieving RRSIG records for {domain} {record_type}...")
    try:
        request = dns.message.make_query(
            domain, record_type, want_dnssec=True)
        response = dns.query.udp(request, RESOLVER_IP, timeout=5)

        rrsig_list = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                for rdata in rrset:
                    # Parse expiration time
                    exp = rdata.expiration
                    inc = rdata.inception
                    exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
                    inc_dt = datetime.fromtimestamp(inc, tz=timezone.utc)
                    now = datetime.now(tz=timezone.utc)
                    days_left = (exp_dt - now).days

                    rrsig_info = {
                        "key_tag": rdata.key_tag,
                        "algorithm": rdata.algorithm,
                        "signer": str(rdata.signer),
                        "inception": inc_dt.strftime("%Y-%m-%d"),
                        "expiration": exp_dt.strftime("%Y-%m-%d"),
                        "days_left": days_left,
                        "expired": days_left < 0
                    }
                    rrsig_list.append(rrsig_info)
                    status = ("EXPIRED" if days_left < 0
                              else f"valid for {days_left} more days")
                    print(f"  [RRSIG] key_tag={rdata.key_tag} "
                          f"inception={rrsig_info['inception']} "
                          f"expiration={rrsig_info['expiration']} "
                          f"({status})")

        if not rrsig_list:
            print(f"  [-] No RRSIG records found")

        return rrsig_list

    except Exception as e:
        print(f"  [-] Error retrieving RRSIG: {e}")
        return []


# ─────────────────────────────────────────────
# STEP 3: Retrieve DS records from parent
# ─────────────────────────────────────────────

def retrieve_ds_records(domain):
    """
    Retrieve DS records from the parent zone.
    Returns list of DS detail dicts.
    """
    print(f"\n[*] Retrieving DS records for {domain} from parent...")
    ds_answer = get_ds_from_parent(domain)
    if not ds_answer:
        print(f"  [-] No DS records found for {domain}")
        return []

    ds_list = []
    for rdata in ds_answer:
        ds_info = {
            "key_tag": rdata.key_tag,
            "algorithm": rdata.algorithm,
            "digest_type": rdata.digest_type,
            "digest": rdata.digest.hex()
        }
        ds_list.append(ds_info)
        print(f"  [DS] key_tag={rdata.key_tag} "
              f"algorithm={rdata.algorithm} "
              f"digest_type={rdata.digest_type} "
              f"digest={rdata.digest.hex()[:20]}...")

    return ds_list


# ─────────────────────────────────────────────
# STEP 4: Detect key lifecycle status
# ─────────────────────────────────────────────

def detect_lifecycle_status(domain, ksks, zsks,
                             ds_list, rrsig_list):
    """
    Analyze key lifecycle by detecting:
    1. Multiple KSKs (KSK rollover in progress)
    2. Multiple ZSKs (ZSK rollover in progress)
    3. DS matches which KSK(s)
    4. DS mismatch (DS points to non-existent key)
    5. RRSIG expiry status

    Returns a status dict with all findings.
    """
    print(f"\n[*] Analyzing key lifecycle for {domain}...")

    observations = []
    status = "NORMAL"
    ds_matched_tags = []
    ds_unmatched_tags = []

    # ── Check for multiple KSKs ──
    if len(ksks) > 1:
        ksk_tags = [k['key_tag'] for k in ksks]
        observations.append(
            f"Multiple KSKs present: key_tags={ksk_tags} "
            f"-- KSK rollover may be in progress")
        status = "KSK Rollover in Progress"

    # ── Check for multiple ZSKs ──
    if len(zsks) > 1:
        zsk_tags = [z['key_tag'] for z in zsks]
        observations.append(
            f"Multiple ZSKs present: key_tags={zsk_tags} "
            f"-- ZSK rollover in progress")
        if status == "NORMAL":
            status = "ZSK Rollover in Progress"

    # ── Check DS match against each KSK ──
    print(f"\n[*] Checking DS match against each KSK...")
    for ksk in ksks:
        ksk_matched = False
        for ds in ds_list:
            if ds['key_tag'] == ksk['key_tag']:
                ksk_matched = True
                ds_matched_tags.append(ksk['key_tag'])
                print(f"  [+] DS matches KSK key_tag={ksk['key_tag']}")
                break

        if not ksk_matched:
            ds_unmatched_tags.append(ksk['key_tag'])
            print(f"  [-] DS does NOT match KSK "
                  f"key_tag={ksk['key_tag']}")

    # ── Determine DS match observations ──
    if ds_matched_tags and ds_unmatched_tags:
        observations.append(
            f"DS matches KSK(s): {ds_matched_tags}")
        observations.append(
            f"DS does NOT match KSK(s): {ds_unmatched_tags} "
            f"-- new KSK not yet published in parent")
        if "KSK Rollover" not in status:
            status = "KSK Rollover in Progress"

    elif ds_matched_tags and not ds_unmatched_tags:
        observations.append(
            f"DS matches all KSK(s): {ds_matched_tags} "
            f"-- chain of trust intact")

    elif not ds_matched_tags and ds_unmatched_tags:
        observations.append(
            f"DS matches NO KSK -- chain of trust broken!")
        status = "DNSSEC BROKEN - DS Mismatch"

    # ── Check RRSIG expiry ──
    for rrsig in rrsig_list:
        if rrsig['expired']:
            observations.append(
                f"RRSIG for key_tag={rrsig['key_tag']} "
                f"EXPIRED on {rrsig['expiration']}")
            status = "DNSSEC BROKEN - Expired RRSIG"
        elif rrsig['days_left'] < 7:
            observations.append(
                f"RRSIG for key_tag={rrsig['key_tag']} "
                f"expiring soon: {rrsig['days_left']} days left")

    # ── Normal status ──
    if status == "NORMAL":
        observations.append(
            "Single KSK and ZSK -- no rollover detected")
        observations.append(
            "DS matches KSK -- chain of trust intact")
        observations.append(
            "All RRSIGs valid -- no expiry issues")

    return {
        "status": status,
        "observations": observations,
        "ds_matched": ds_matched_tags,
        "ds_unmatched": ds_unmatched_tags,
        "ksk_count": len(ksks),
        "zsk_count": len(zsks)
    }


# ─────────────────────────────────────────────
# MAIN: Key Lifecycle Analysis
# ─────────────────────────────────────────────

def analyze_key_lifecycle(domain):
    """
    Main function to analyze DNSSEC key lifecycle.
    Uses Q1 functions to retrieve DNSKEY, RRSIG, DS
    and detects rollover status and DS mismatches.
    """
    print("=" * 60)
    print(f"  DNSSEC Key Lifecycle Analyzer")
    print(f"  Domain: {domain}")
    print("=" * 60)

    # Step 1: Retrieve DNSKEYs
    result = retrieve_dnskeys(domain)
    if not result[0]:
        return {"domain": domain, "status": "ERROR",
                "observations": ["Could not retrieve DNSKEY"]}

    key_list, ksks, zsks, keys, dnskey_answer = result

    # Step 2: Retrieve RRSIGs for DNSKEY
    rrsig_list = retrieve_rrsigs(domain, "DNSKEY")

    # Also get RRSIG for A record to show ZSK usage
    rrsig_a = retrieve_rrsigs(domain, "A")

    # Step 3: Retrieve DS from parent
    ds_list = retrieve_ds_records(domain)

    # Step 4: Detect lifecycle status
    lifecycle = detect_lifecycle_status(
        domain, ksks, zsks, ds_list, rrsig_list)

    return {
        "domain": domain,
        "status": lifecycle["status"],
        "observations": lifecycle["observations"],
        "ksk_count": lifecycle["ksk_count"],
        "zsk_count": lifecycle["zsk_count"],
        "ds_matched": lifecycle["ds_matched"],
        "ds_unmatched": lifecycle["ds_unmatched"],
        "rrsigs": rrsig_list
    }


# ─────────────────────────────────────────────
# PRINT FINAL OUTPUT
# ─────────────────────────────────────────────

def print_result(result):
    """Print lifecycle analysis in required format."""
    print("\n" + "=" * 60)
    print(f"  Domain: {result['domain']}")
    print(f"  Status: {result['status']}")
    print(f"\n  Observations:")
    for obs in result['observations']:
        print(f"    - {obs}")
    print()
    print(f"  Key Summary:")
    print(f"    KSKs found : {result.get('ksk_count', 'N/A')}")
    print(f"    ZSKs found : {result.get('zsk_count', 'N/A')}")
    if result.get('ds_matched'):
        print(f"    DS matched : {result['ds_matched']}")
    if result.get('ds_unmatched'):
        print(f"    DS missing : {result['ds_unmatched']}")
    print("=" * 60)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Test multiple domains to show different lifecycle states
    domains = ["example.com", "cloudflare.com", "google.com"]

    if len(sys.argv) >= 2:
        domains = sys.argv[1:]

    for domain in domains:
        result = analyze_key_lifecycle(domain)
        print_result(result)
        print()