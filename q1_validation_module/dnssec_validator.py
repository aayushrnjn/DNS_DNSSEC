#!/usr/bin/env python3
"""
Q1: DNSSEC Validation Module

This module performs DNSSEC validation for a given domain and record type.
It retrieves DNSKEY, RRSIG, DS records and validates the chain of trust.
"""

import sys
import dns.resolver
import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rdataset
import dns.query
import dns.message
import dns.flags


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

# We use Google's public DNS which supports DNSSEC
RESOLVER_IP = "8.8.8.8"


def make_resolver():
    """Create a DNS resolver that requests DNSSEC records."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [RESOLVER_IP]
    resolver.use_edns(0, dns.flags.DO, 4096)  # Set DNSSEC OK bit
    return resolver


# ─────────────────────────────────────────────
# STEP 1: Fetch Answer Records (A, AAAA, etc.)
# ─────────────────────────────────────────────

def get_answer_records(domain, record_type):
    """
    Fetch the actual answer records for the domain.
    e.g. A records, AAAA records etc.
    Returns the answer rrset or None if not found.
    """
    print(f"\n[*] Fetching {record_type} records for {domain}...")
    try:
        resolver = make_resolver()
        answer = resolver.resolve(domain, record_type)
        print(f"[+] Found {len(answer)} {record_type} record(s):")
        for rdata in answer:
            print(f"    {domain} -> {rdata}")
        return answer
    except dns.resolver.NXDOMAIN:
        print(f"[-] Domain {domain} does not exist.")
        return None
    except dns.resolver.NoAnswer:
        print(f"[-] No {record_type} records found for {domain}.")
        return None
    except Exception as e:
        print(f"[-] Error fetching {record_type} records: {e}")
        return None


# ─────────────────────────────────────────────
# STEP 2: Fetch DNSKEY Records
# ─────────────────────────────────────────────

def get_dnskey(domain):
    """
    Fetch DNSKEY records for the domain.
    Returns a list of (flags, protocol, algorithm, key) tuples.
    DNSKEY contains both ZSK (Zone Signing Key) and KSK (Key Signing Key).
    flags=256 means ZSK, flags=257 means KSK.
    """
    print(f"\n[*] Fetching DNSKEY records for {domain}...")
    try:
        resolver = make_resolver()
        answer = resolver.resolve(domain, "DNSKEY")
        keys = {}
        keys[dns.name.from_text(domain)] = answer

        print(f"[+] Found {len(answer)} DNSKEY record(s):")
        for rdata in answer:
            key_type = "KSK" if rdata.flags == 257 else "ZSK"
            print(f"    [{key_type}] flags={rdata.flags} "
                  f"algorithm={rdata.algorithm} "
                  f"key_tag={dns.dnssec.key_id(rdata)}")
        return keys, answer
    except Exception as e:
        print(f"[-] Error fetching DNSKEY: {e}")
        return None, None


# ─────────────────────────────────────────────
# STEP 3: Fetch RRSIG Records
# ─────────────────────────────────────────────

def get_rrsig(domain, record_type):
    """
    Fetch RRSIG (Resource Record Signature) for the given record type.
    RRSIG is the digital signature over the DNS records.
    It is created using the ZSK private key.
    """
    print(f"\n[*] Fetching RRSIG for {domain} {record_type}...")
    try:
        # We need to send a raw DNS query with DO bit set
        request = dns.message.make_query(
            domain,
            record_type,
            want_dnssec=True
        )
        response = dns.query.udp(request, RESOLVER_IP, timeout=5)

        # Extract RRSIG from the answer section
        rrsig_list = []
        answer_rrset = None

        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_list.append(rrset)
                print(f"[+] Found RRSIG:")
                for rdata in rrset:
                    print(f"    covers={dns.rdatatype.to_text(rdata.type_covered)} "
                          f"algorithm={rdata.algorithm} "
                          f"key_tag={rdata.key_tag} "
                          f"signer={rdata.signer}")
            else:
                answer_rrset = rrset

        if not rrsig_list:
            print(f"[-] No RRSIG found for {domain} {record_type}")
            return None, None

        return answer_rrset, rrsig_list

    except Exception as e:
        print(f"[-] Error fetching RRSIG: {e}")
        return None, None


# ─────────────────────────────────────────────
# STEP 4: Fetch DS Record from Parent Zone
# ─────────────────────────────────────────────

def get_ds_from_parent(domain):
    """
    Fetch the DS (Delegation Signer) record from the parent zone.
    The DS record is stored in the parent zone and contains
    a hash of the child zone's KSK.
    e.g. for example.com, the DS record is in .com zone.
    """
    print(f"\n[*] Fetching DS record for {domain} from parent zone...")
    try:
        resolver = make_resolver()
        answer = resolver.resolve(domain, "DS")
        print(f"[+] Found {len(answer)} DS record(s):")
        for rdata in answer:
            print(f"    key_tag={rdata.key_tag} "
                  f"algorithm={rdata.algorithm} "
                  f"digest_type={rdata.digest_type} "
                  f"digest={rdata.digest.hex()[:20]}...")
        return answer
    except dns.resolver.NoAnswer:
        print(f"[-] No DS record found for {domain} "
              f"(zone may not be DNSSEC signed or is root).")
        return None
    except Exception as e:
        print(f"[-] Error fetching DS record: {e}")
        return None


# ─────────────────────────────────────────────
# STEP 5: Verify RRSIG using DNSKEY (ZSK)
# ─────────────────────────────────────────────

def verify_rrsig(domain, answer_rrset, rrsig_list, keys):
    """
    Verify the RRSIG signature using the DNSKEY (ZSK).
    This confirms that the DNS records were signed by the zone owner.
    Uses dns.dnssec.validate() which handles the crypto internally.
    """
    print(f"\n[*] Verifying RRSIG using DNSKEY (ZSK)...")
    if not answer_rrset or not rrsig_list or not keys:
        print("[-] Missing data for RRSIG verification.")
        return False

    try:
        for rrsig_rrset in rrsig_list:
            dns.dnssec.validate(
                answer_rrset,
                rrsig_rrset,
                keys
            )
        print("[+] RRSIG verified successfully using ZSK.")
        return True
    except dns.dnssec.ValidationFailure as e:
        print(f"[-] RRSIG verification FAILED: {e}")
        return False
    except Exception as e:
        print(f"[-] Error during RRSIG verification: {e}")
        return False


# ─────────────────────────────────────────────
# STEP 6: Verify DNSKEY using DS (Chain Step)
# ─────────────────────────────────────────────

def verify_dnskey_with_ds(domain, dnskey_answer, ds_answer):
    """
    Verify the DNSKEY (KSK) using the DS record from the parent zone.
    This is the chain of trust step:
      Parent DS digest == hash(child KSK)
    This ensures the KSK is authentic and trusted by the parent.
    """
    print(f"\n[*] Verifying DNSKEY using DS record (chain of trust)...")
    if not dnskey_answer or not ds_answer:
        print("[-] Missing DNSKEY or DS records.")
        return False

    try:
        # Check each DS record against each DNSKEY
        for ds_rdata in ds_answer:
            for dnskey_rdata in dnskey_answer:
                # Only check KSK (flags=257)
                if dnskey_rdata.flags != 257:
                    continue

                # Compute the DS digest from the DNSKEY
                name = dns.name.from_text(domain)
                computed_ds = dns.dnssec.make_ds(
                    name,
                    dnskey_rdata,
                    ds_rdata.digest_type
                )

                # Compare key_tag and digest
                if (computed_ds.key_tag == ds_rdata.key_tag and
                        computed_ds.digest == ds_rdata.digest):
                    print(f"[+] DS record matches KSK "
                          f"(key_tag={ds_rdata.key_tag}).")
                    print(f"[+] Chain of trust verified: "
                          f"Parent DS → Child KSK.")
                    return True

        print("[-] No matching DS record found for any KSK.")
        return False

    except Exception as e:
        print(f"[-] Error during DS verification: {e}")
        return False


# ─────────────────────────────────────────────
# MAIN VALIDATION FUNCTION (reusable)
# ─────────────────────────────────────────────

def validate_dnssec(domain, record_type):
    """
    Main reusable DNSSEC validation function.
    This is the function that Q2, Q3, Q4 will import and use.

    Parameters:
        domain      : str  - e.g. "example.com"
        record_type : str  - e.g. "A", "AAAA", "MX"

    Returns:
        dict with validation result and step details
    """
    print("=" * 60)
    print(f"  DNSSEC Validation")
    print(f"  Domain : {domain}")
    print(f"  Record : {record_type}")
    print("=" * 60)

    steps = []
    result = {
        "domain": domain,
        "record_type": record_type,
        "valid": False,
        "steps": steps,
        "failure_reason": None
    }

    # --- Step 1: Get answer records ---
    answer = get_answer_records(domain, record_type)
    if answer is None:
        result["failure_reason"] = f"No {record_type} records found"
        return result

    # --- Step 2: Get DNSKEY ---
    keys, dnskey_answer = get_dnskey(domain)
    if keys is None:
        result["failure_reason"] = "Could not retrieve DNSKEY"
        return result
    steps.append("DNSKEY retrieved")

    # --- Step 3: Get RRSIG ---
    answer_rrset, rrsig_list = get_rrsig(domain, record_type)
    if rrsig_list is None:
        result["failure_reason"] = "Could not retrieve RRSIG"
        return result

    # --- Step 4: Get DS from parent ---
    ds_answer = get_ds_from_parent(domain)
    if ds_answer is None:
        result["failure_reason"] = "Could not retrieve DS from parent"
        return result

    # --- Step 5: Verify RRSIG using DNSKEY ---
    rrsig_valid = verify_rrsig(domain, answer_rrset, rrsig_list, keys)
    if not rrsig_valid:
        result["failure_reason"] = "RRSIG verification failed"
        return result
    steps.append("RRSIG verified using ZSK")

    # --- Step 6: Verify DNSKEY using DS ---
    ds_valid = verify_dnskey_with_ds(domain, dnskey_answer, ds_answer)
    if not ds_valid:
        result["failure_reason"] = "DS verification failed"
        return result
    steps.append("DS matched parent")

    # All steps passed
    result["valid"] = True
    return result


# ─────────────────────────────────────────────
# PRINT FINAL OUTPUT
# ─────────────────────────────────────────────

def print_result(result):
    """Print the final validation result in the required format."""
    print("\n" + "=" * 60)
    print(f"  Domain: {result['domain']}")
    print(f"  Record: {result['record_type']}")
    status = "VALID" if result["valid"] else "INVALID"
    print(f"  DNSSEC Validation: {status}")
    print()
    if result["steps"]:
        print("  Steps:")
        for step in result["steps"]:
            print(f"    • {step}")
    if result["failure_reason"]:
        print(f"\n  Failure Reason:")
        print(f"    • {result['failure_reason']}")
    print("=" * 60)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Default test domain
    domain = "example.com"
    record_type = "A"

    # Accept command line arguments
    if len(sys.argv) == 3:
        domain = sys.argv[1]
        record_type = sys.argv[2].upper()
    elif len(sys.argv) != 1:
        print("Usage: python3 dnssec_validator.py <domain> <record_type>")
        print("Example: python3 dnssec_validator.py example.com A")
        sys.exit(1)

    result = validate_dnssec(domain, record_type)
    print_result(result)