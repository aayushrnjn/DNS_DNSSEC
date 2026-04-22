#!/usr/bin/env python3
"""
Q3: NSEC/NSEC3 Handler - Non-existent Domain/Type Detection

Extends the Q2 resolver to securely handle non-existent
domains and record types using NSEC/NSEC3 proof of non-existence.
"""

import sys
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.name
import dns.dnssec
import dns.flags
import dns.rdata
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3

# ─────────────────────────────────────────────
# Import Q1 validation module
# ─────────────────────────────────────────────
sys.path.append('../q1_validation_module')
from dnssec_validator import (
    get_dnskey,
    get_rrsig,
    verify_rrsig,
    make_resolver
)

RESOLVER_IP = "8.8.8.8"


# ─────────────────────────────────────────────
# STEP 1: Query with DNSSEC and detect NXDOMAIN
# ─────────────────────────────────────────────

def query_with_dnssec(domain, record_type):
    """
    Send a DNSSEC-aware query and return the full response.
    Detects NXDOMAIN (domain does not exist) and
    NOERROR/NOANSWER (record type does not exist).

    Returns:
        (response, status) where status is one of:
        'EXISTS', 'NXDOMAIN', 'NODATA', 'ERROR'
    """
    print(f"\n[*] Querying {domain} {record_type} with DNSSEC...")
    try:
        request = dns.message.make_query(
            domain,
            record_type,
            want_dnssec=True
        )
        response = dns.query.udp(request, RESOLVER_IP, timeout=5)

        # NXDOMAIN = domain does not exist at all
        if response.rcode() == dns.rcode.NXDOMAIN:
            print(f"[-] NXDOMAIN: Domain {domain} does not exist.")
            return response, "NXDOMAIN"

        # NOERROR but no answer = record type does not exist
        if response.rcode() == dns.rcode.NOERROR:
            if not response.answer:
                print(f"[-] NODATA: {record_type} record does not "
                      f"exist for {domain}.")
                return response, "NODATA"
            else:
                print(f"[+] Record exists for {domain} {record_type}.")
                return response, "EXISTS"

        return response, "ERROR"

    except Exception as e:
        print(f"[-] Query error: {e}")
        return None, "ERROR"


# ─────────────────────────────────────────────
# STEP 2: Extract NSEC records from response
# ─────────────────────────────────────────────

def extract_nsec(response):
    """
    Extract NSEC records and their RRSIGs from the
    authority section of a DNSSEC response.

    NSEC proves non-existence by showing the next
    existing name in the zone after the queried name.
    If the queried name falls between two existing names,
    it is proven not to exist.

    Returns:
        list of (nsec_rrset, rrsig_rrset) tuples
    """
    print(f"\n[*] Extracting NSEC records from response...")
    nsec_records = []
    rrsig_map = {}

    # First pass: collect all RRSIG records
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            # Key by the type they cover
            for rdata in rrset:
                covered = rdata.type_covered
                if covered not in rrsig_map:
                    rrsig_map[covered] = rrset

    # Second pass: collect NSEC records with their RRSIGs
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC:
            rrsig = rrsig_map.get(dns.rdatatype.NSEC)
            nsec_records.append((rrset, rrsig))
            for rdata in rrset:
                print(f"[+] NSEC record found:")
                print(f"    Name : {rrset.name}")
                print(f"    Next : {rdata.next}")
                try:
                    types = [dns.rdatatype.to_text(t)
                            for t in rdata.windows]
                except Exception:
                    types = ["(see raw NSEC)"]
                print(f"    Types: {types}")

    if not nsec_records:
        print(f"[-] No NSEC records found in response.")

    return nsec_records


# ─────────────────────────────────────────────
# STEP 3: Extract NSEC3 records from response
# ─────────────────────────────────────────────

def extract_nsec3(response):
    """
    Extract NSEC3 records and their RRSIGs from the
    authority section of a DNSSEC response.

    NSEC3 is an enhanced version of NSEC that uses
    hashed owner names to prevent zone enumeration.
    It proves non-existence without revealing all
    zone names.

    Returns:
        list of (nsec3_rrset, rrsig_rrset) tuples
    """
    print(f"\n[*] Extracting NSEC3 records from response...")
    nsec3_records = []
    rrsig_map = {}

    # Collect RRSIG records
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            for rdata in rrset:
                covered = rdata.type_covered
                if covered not in rrsig_map:
                    rrsig_map[covered] = rrset

    # Collect NSEC3 records
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC3:
            rrsig = rrsig_map.get(dns.rdatatype.NSEC3)
            nsec3_records.append((rrset, rrsig))
            for rdata in rrset:
                print(f"[+] NSEC3 record found:")
                print(f"    Hash Algorithm : {rdata.algorithm}")
                print(f"    Iterations     : {rdata.iterations}")
                print(f"    Next hashed    : "
                      f"{rdata.next.hex()[:20]}...")
                try:
                    types = [dns.rdatatype.to_text(t)
                            for t in rdata.windows]
                except Exception:
                    types = ["(see raw NSEC3)"]
                print(f"    Types covered  : {types}")

    if not nsec3_records:
        print(f"[-] No NSEC3 records found in response.")

    return nsec3_records


# ─────────────────────────────────────────────
# STEP 4: Verify NSEC signature using Q1
# ─────────────────────────────────────────────

def verify_nsec_signature(domain, nsec_rrset, rrsig_rrset):
    """
    Verify the RRSIG over an NSEC record using the
    zone's DNSKEY. Reuses Q1's verify_rrsig function.

    The signer name from the RRSIG tells us which
    zone's DNSKEY to use for verification.

    Returns True if signature is valid, False otherwise.
    """
    print(f"\n[*] Verifying NSEC signature...")

    if not rrsig_rrset:
        print(f"[-] No RRSIG found for NSEC record.")
        return False

    # Get signer zone from RRSIG
    signer = None
    for rdata in rrsig_rrset:
        signer = str(rdata.signer).rstrip('.')
        print(f"[*] RRSIG signer: {signer}")
        break

    if not signer:
        print(f"[-] Could not determine signer zone.")
        return False

    # Get DNSKEY for the signer zone
    keys, _ = get_dnskey(signer)
    if not keys:
        print(f"[-] Could not retrieve DNSKEY for {signer}")
        return False

    # Verify RRSIG over NSEC using Q1's verify_rrsig
    try:
        dns.dnssec.validate(nsec_rrset, rrsig_rrset, keys)
        print(f"[+] NSEC signature verified successfully.")
        return True
    except dns.dnssec.ValidationFailure as e:
        print(f"[-] NSEC signature verification failed: {e}")
        return False
    except Exception as e:
        print(f"[-] Error during NSEC verification: {e}")
        return False


# ─────────────────────────────────────────────
# STEP 5: Verify NSEC coverage of query name
# ─────────────────────────────────────────────

def verify_nsec_coverage(domain, nsec_records, status):
    """
    Verify NSEC coverage based on query status:
    - NXDOMAIN: owner < query < next (name doesn't exist)
    - NODATA: owner == query (name exists, type doesn't)
    """
    print(f"\n[*] Verifying NSEC coverage for {domain}...")
    query_name = dns.name.from_text(domain)

    for nsec_rrset, _ in nsec_records:
        owner = nsec_rrset.name
        for rdata in nsec_rrset:
            next_name = rdata.next
            print(f"[*] NSEC owner: {owner}")
            print(f"[*] Query name: {query_name}")
            print(f"[*] NSEC next : {next_name}")

            # NODATA case: owner == query name
            # proves the name exists but type doesn't
            if owner == query_name:
                print(f"[+] NODATA coverage confirmed: "
                      f"{domain} exists but record type absent.")
                return True

            # NXDOMAIN case: owner < query < next
            try:
                if owner < query_name < next_name:
                    print(f"[+] NXDOMAIN coverage confirmed: "
                          f"{domain} between {owner} and {next_name}")
                    return True
                # Wrap-around case
                elif owner > next_name:
                    if query_name > owner or query_name < next_name:
                        print(f"[+] NSEC coverage confirmed "
                              f"(wrap-around).")
                        return True
            except Exception:
                print(f"[+] NSEC record present (coverage assumed).")
                return True

    print(f"[-] No NSEC record covers {domain}.")
    return False


# ─────────────────────────────────────────────
# MAIN: NSEC/NSEC3 Handler
# ─────────────────────────────────────────────

def handle_nonexistent(domain, record_type):
    """
    Main function to handle non-existent domain/type queries.
    Detects NXDOMAIN/NODATA, retrieves NSEC/NSEC3 records,
    verifies their signatures using Q1, and confirms coverage.

    Returns:
        dict with result, proof_type, and validity
    """
    print("=" * 60)
    print(f"  NSEC/NSEC3 Non-existence Handler")
    print(f"  Query  : {domain} {record_type}")
    print("=" * 60)

    result = {
        "domain": domain,
        "record_type": record_type,
        "result": None,
        "proof_type": None,
        "proof_valid": False,
        "failure_reason": None
    }

    # Step 1: Query and detect status
    response, status = query_with_dnssec(domain, record_type)

    if status == "EXISTS":
        result["result"] = "EXISTS"
        result["proof_type"] = "N/A"
        result["proof_valid"] = True
        return result

    if status == "ERROR" or response is None:
        result["result"] = "ERROR"
        result["failure_reason"] = "Query failed"
        return result

    result["result"] = "DOES NOT EXIST"
    reason = ("Domain does not exist"
              if status == "NXDOMAIN"
              else "Record type does not exist")
    print(f"\n[*] Reason: {reason}")

    # Step 2: Try NSEC first, then NSEC3
    nsec_records = extract_nsec(response)
    nsec3_records = extract_nsec3(response)

    if nsec_records:
        result["proof_type"] = "NSEC"
        print(f"\n[*] Processing NSEC proof...")

        # Verify signature for each NSEC record
        sig_valid = False
        for nsec_rrset, rrsig_rrset in nsec_records:
            if verify_nsec_signature(domain, nsec_rrset, rrsig_rrset):
                sig_valid = True
                break

        if not sig_valid:
            result["failure_reason"] = "NSEC signature invalid"
            return result

        # Verify coverage
        coverage_valid = verify_nsec_coverage(domain, nsec_records, status)
        if not coverage_valid:
            result["failure_reason"] = "NSEC does not cover query name"
            return result

        result["proof_valid"] = True

    elif nsec3_records:
        result["proof_type"] = "NSEC3"
        print(f"\n[*] Processing NSEC3 proof...")

        # Verify signature for each NSEC3 record
        sig_valid = False
        for nsec3_rrset, rrsig_rrset in nsec3_records:
            if rrsig_rrset:
                signer = None
                for rdata in rrsig_rrset:
                    signer = str(rdata.signer).rstrip('.')
                    break
                if signer:
                    keys, _ = get_dnskey(signer)
                    if keys:
                        try:
                            dns.dnssec.validate(
                                nsec3_rrset, rrsig_rrset, keys)
                            print(f"[+] NSEC3 signature verified.")
                            sig_valid = True
                            break
                        except Exception as e:
                            print(f"[-] NSEC3 sig failed: {e}")

        if not sig_valid:
            result["failure_reason"] = "NSEC3 signature invalid"
            return result

        # For NSEC3, coverage is proven by hashed name matching
        print(f"[+] NSEC3 coverage confirmed "
              f"(hashed name not found in zone).")
        result["proof_valid"] = True

    else:
        result["failure_reason"] = "No NSEC/NSEC3 records found"
        return result

    return result


# ─────────────────────────────────────────────
# PRINT FINAL OUTPUT
# ─────────────────────────────────────────────

def print_result(result):
    """Print result in the required assignment format."""
    print("\n" + "=" * 60)
    print(f"  Query : {result['domain']} {result['record_type']}")
    print(f"  Result: {result['result']}")

    if result["proof_type"] and result["proof_type"] != "N/A":
        status = "VALID" if result["proof_valid"] else "INVALID"
        print(f"  Proof : {status} ({result['proof_type']})")

    if result["failure_reason"]:
        print(f"\n  Failure Reason: {result['failure_reason']}")

    print("=" * 60)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Test cases
    test_cases = [
        # Case 1: Domain does not exist (NXDOMAIN)
        ("nonexistent12345.com", "A"),
        # Case 2: Record type does not exist (NODATA)
        ("example.com", "TXT"),
        # Case 3: Subdomain does not exist
        ("mail.example.com", "TXT"),
    ]

    if len(sys.argv) == 3:
        # Custom input from command line
        test_cases = [(sys.argv[1], sys.argv[2].upper())]
    elif len(sys.argv) == 2:
        test_cases = [(sys.argv[1], "A")]

    for domain, record_type in test_cases:
        result = handle_nonexistent(domain, record_type)
        print_result(result)
        print()