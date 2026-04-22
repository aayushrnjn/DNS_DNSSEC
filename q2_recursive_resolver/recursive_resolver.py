"""
Q2: Recursive Resolver with DNSSEC Validation

Implements a recursive resolver that starts from root,
resolves Root -> TLD -> Authoritative, and validates
DNSSEC at each step using the Q1 validation module.
"""

import sys
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.rdataset
import dns.name
import dns.dnssec
import dns.flags
import dns.rdata

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

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

# Real root nameserver (a.root-servers.net)
ROOT_SERVER = "198.41.0.4"
RESOLVER_IP = "8.8.8.8"  # fallback for DNSSEC validation


# ─────────────────────────────────────────────
# HELPER: Send DNS query to a specific server
# ─────────────────────────────────────────────

def send_query(domain, record_type, server, want_dnssec=True):
    """
    Send a DNS query directly to a specific nameserver.
    Returns the response message or None on failure.
    """
    try:
        request = dns.message.make_query(
            domain,
            record_type,
            want_dnssec=want_dnssec
        )
        response = dns.query.udp(request, server, timeout=5)
        return response
    except Exception as e:
        print(f"    [-] Query failed to {server}: {e}")
        return None


# ─────────────────────────────────────────────
# HELPER: Extract NS + glue records from response
# ─────────────────────────────────────────────

def extract_nameserver_ip(response):
    """
    Extract the IP address of a nameserver from the
    authority and additional sections of a DNS response.
    Returns the first available nameserver IP or None.
    """
    # Build a map of NS name -> IP from additional section
    glue = {}
    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A:
            for rdata in rrset:
                glue[str(rrset.name)] = str(rdata)

    # Find NS records in authority section
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for rdata in rrset:
                ns_name = str(rdata.target)
                if ns_name in glue:
                    return glue[ns_name], ns_name
                # Try with trailing dot
                if ns_name + "." in glue:
                    return glue[ns_name + "."], ns_name

    return None, None


# ─────────────────────────────────────────────
# STEP: Validate DNSSEC at a zone level
# ─────────────────────────────────────────────

def validate_zone_dnssec(zone, record_type="A"):
    """
    Validate DNSSEC for a given zone using Q1 functions.
    Validates:
      1. DNSKEY retrieval
      2. RRSIG verification using ZSK
      3. DS chain verification from parent

    Returns True if valid, False otherwise.
    """
    print(f"\n    [DNSSEC] Validating zone: {zone}")

    # Get DNSKEY
    keys, dnskey_answer = get_dnskey(zone)
    if not keys:
        print(f"    [DNSSEC] Could not retrieve DNSKEY for {zone}")
        return False
    print(f"    [DNSSEC] DNSKEY retrieved for {zone}")

    # Get RRSIG for DNSKEY record itself
    answer_rrset, rrsig_list = get_rrsig(zone, "DNSKEY")
    if not rrsig_list:
        print(f"    [DNSSEC] No RRSIG found for DNSKEY of {zone}")
        return False

    # Verify RRSIG using DNSKEY
    rrsig_valid = verify_rrsig(zone, answer_rrset, rrsig_list, keys)
    if not rrsig_valid:
        print(f"    [DNSSEC] RRSIG verification failed for {zone}")
        return False
    print(f"    [DNSSEC] RRSIG verified for {zone}")

    # Get DS from parent and verify chain
    # Skip DS check for root (no parent)
    if zone != ".":
        ds_answer = get_ds_from_parent(zone)
        if not ds_answer:
            print(f"    [DNSSEC] No DS record found for {zone}")
            return False
        ds_valid = verify_dnskey_with_ds(zone, dnskey_answer, ds_answer)
        if not ds_valid:
            print(f"    [DNSSEC] DS chain verification failed for {zone}")
            return False
        print(f"    [DNSSEC] DS chain verified for {zone}")

    return True


# ─────────────────────────────────────────────
# CORE: Recursive Resolution
# ─────────────────────────────────────────────

def recursive_resolve(domain, record_type="A"):
    """
    Perform recursive DNS resolution starting from root.
    At each step:
      1. Query the current nameserver
      2. Validate DNSSEC for the current zone
      3. Follow referrals until we get the final answer

    Returns:
        dict with ip, dnssec_status, path, and step details
    """
    print("\n" + "=" * 60)
    print(f"  Recursive Resolver")
    print(f"  Query  : {domain}")
    print(f"  Type   : {record_type}")
    print("=" * 60)

    path = []
    steps = []
    current_server = ROOT_SERVER
    current_zone = "."
    final_ip = None
    dnssec_verified = True

    # Labels to resolve: e.g. example.com -> ['.', 'com', 'example.com']
    domain_labels = build_resolution_path(domain)

    for zone_label in domain_labels:
        print(f"\n{'─'*50}")
        print(f"  Step: Querying zone [{zone_label}]")
        print(f"  Server: {current_server}")
        print(f"{'─'*50}")

        # ── Query current nameserver ──
        response = send_query(domain, record_type, current_server)
        if not response:
            print(f"  [!] No response from {current_server}, using fallback...")
            path.append(zone_label)
            step_valid = validate_zone_dnssec(zone_label)
            if not step_valid:
                dnssec_verified = False
            steps.append({
                "zone": zone_label,
                "server": current_server,
                "dnssec": step_valid
            })
            if not final_ip:
                final_ip = fallback_resolve(domain, record_type)
            break

        # ── Check if we got a final answer ──
        if response.answer:
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.A:
                    for rdata in rrset:
                        final_ip = str(rdata)
            print(f"  [+] Got answer: {final_ip}")
            path.append(zone_label)

            # Validate DNSSEC for this zone
            step_valid = validate_zone_dnssec(zone_label)
            if not step_valid:
                dnssec_verified = False
            steps.append({
                "zone": zone_label,
                "server": current_server,
                "dnssec": step_valid
            })
            break

        # ── Follow referral to next nameserver ──
        next_server_ip, next_ns_name = extract_nameserver_ip(response)

        if next_server_ip:
            print(f"  [+] Referral to: {next_ns_name} ({next_server_ip})")
            path.append(zone_label)

            # Validate DNSSEC for current zone
            step_valid = validate_zone_dnssec(zone_label)
            if not step_valid:
                dnssec_verified = False

            steps.append({
                "zone": zone_label,
                "server": current_server,
                "dnssec": step_valid
            })
            current_server = next_server_ip
            current_zone = zone_label
        else:
            # No glue records — use fallback resolver
            print(f"  [!] No glue records, using fallback resolver")
            path.append(zone_label)

            # Still validate DNSSEC using Google DNS
            step_valid = validate_zone_dnssec(zone_label)
            if not step_valid:
                dnssec_verified = False

            steps.append({
                "zone": zone_label,
                "server": current_server,
                "dnssec": step_valid
            })

            # Resolve final answer via fallback
            if not final_ip:
                final_ip = fallback_resolve(domain, record_type)
            break

    return {
        "domain": domain,
        "record_type": record_type,
        "ip": final_ip,
        "dnssec": "VERIFIED" if dnssec_verified else "FAILED",
        "path": path,
        "steps": steps
    }


# ─────────────────────────────────────────────
# HELPER: Build resolution path labels
# ─────────────────────────────────────────────

def build_resolution_path(domain):
    """
    Build the list of zones to traverse for resolution.
    e.g. example.com -> ['.', 'com', 'example.com']
    e.g. www.example.com -> ['.', 'com', 'example.com', 'www.example.com']
    """
    parts = domain.rstrip('.').split('.')
    path = ['.']

    # Build from TLD inward
    for i in range(len(parts) - 1, -1, -1):
        zone = '.'.join(parts[i:])
        path.append(zone)

    return path


# ─────────────────────────────────────────────
# HELPER: Fallback resolver
# ─────────────────────────────────────────────

def fallback_resolve(domain, record_type):
    """
    Fallback to Google DNS for final answer resolution.
    Used when glue records are not available.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [RESOLVER_IP]
        answer = resolver.resolve(domain, record_type)
        for rdata in answer:
            return str(rdata)
    except Exception as e:
        print(f"    [-] Fallback resolve failed: {e}")
        return None


# ─────────────────────────────────────────────
# PRINT FINAL OUTPUT
# ─────────────────────────────────────────────

def print_result(result):
    """Print the final resolution result in required format."""
    print("\n" + "=" * 60)
    print(f"  Query : {result['domain']}")
    print(f"  IP    : {result['ip']}")
    print(f"  DNSSEC: {result['dnssec']}")
    print()
    print("  Path:")

    # Build path string
    path_str = " → ".join(result['path'])
    print(f"    {path_str}")

    print()
    print("  Step Details:")
    for step in result['steps']:
        status = "✓ DNSSEC OK" if step['dnssec'] else "✗ DNSSEC FAIL"
        print(f"    [{status}] {step['zone']} via {step['server']}")

    print("=" * 60)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    domain = "example.com"
    record_type = "A"

    if len(sys.argv) == 3:
        domain = sys.argv[1]
        record_type = sys.argv[2].upper()
    elif len(sys.argv) == 2:
        domain = sys.argv[1]
    elif len(sys.argv) != 1:
        print("Usage: python3 recursive_resolver.py <domain> [record_type]")
        print("Example: python3 recursive_resolver.py example.com A")
        sys.exit(1)

    result = recursive_resolve(domain, record_type)
    print_result(result)