# Programming Assignment 2 - DNS and DNSSEC

**Course:** CS6903: Network Security

**Student:** Aayush Ranjan (cs25mtech11002)

**Institution:** IIT Hyderabad

**Deadline:** 22nd April 2026

---

## System Description

- OS: macOS (Apple Silicon)
- Python: 3.9.6
- dnspython: 2.7.0
- cryptography: 46.0.7
- Docker: 29.4.0
- IDE: Visual Studio Code

---

## Project Structure

    NS Ass2/
        q1_validation_module/
            dnssec_validator.py
        q2_recursive_resolver/
            recursive_resolver.py
        q3_nsec_handling/
            nsec_handler.py
        q4_key_lifecycle/
            key_lifecycle.py
        q5_tampering_demo/
            q5_validator.py
            Labsetup-arm/
        report/
            images/
            report.pdf
        README.md

---

## Dependencies Installation

Run these commands on your Mac before starting:

    pip3 install dnspython
    pip3 install cryptography

Verify installation:

    python3 -c "import dns.resolver; print('dnspython OK')"
    python3 -c "import cryptography; print('cryptography OK')"

---

## Q1: DNSSEC Validation Module

**File:** q1_validation_module/dnssec_validator.py

**Description:**
Reusable DNSSEC validation module that retrieves DNSKEY, RRSIG,
DS records and validates the full chain of trust. This module is
imported by Q2, Q3, Q4, and Q5.

**How to run:**

    cd q1_validation_module
    python3 dnssec_validator.py <domain> <record_type>

**Examples:**

    python3 dnssec_validator.py example.com A
    python3 dnssec_validator.py cloudflare.com A

**Expected Output:**

    Domain: example.com
    Record: A
    DNSSEC Validation: VALID
    Steps:
      - DNSKEY retrieved
      - RRSIG verified using ZSK
      - DS matched parent

---

## Q2: Recursive Resolver

**File:** q2_recursive_resolver/recursive_resolver.py

**Description:**
Recursive DNS resolver starting from root server (198.41.0.4).
Resolves Root to TLD to Authoritative with DNSSEC validation
at each step. Imports Q1 module.

**How to run:**

    cd q2_recursive_resolver
    python3 recursive_resolver.py <domain> [record_type]

**Examples:**

    python3 recursive_resolver.py example.com A
    python3 recursive_resolver.py cloudflare.com A

**Expected Output:**

    Query : example.com
    IP    : 104.20.23.154
    DNSSEC: VERIFIED
    Path:
      . -> com -> example.com

---

## Q3: NSEC/NSEC3 Non-existence Handler

**File:** q3_nsec_handling/nsec_handler.py

**Description:**
Handles non-existent domains (NXDOMAIN) and missing record types
(NODATA) using NSEC/NSEC3 cryptographic proof of non-existence.
Imports Q1 module.

**How to run:**

    cd q3_nsec_handling
    python3 nsec_handler.py <domain> <record_type>

**Examples:**

    python3 nsec_handler.py mail.example.com TXT
    python3 nsec_handler.py nonexistent12345.com A
    python3 nsec_handler.py example.com TXT

**Expected Output:**

    Query : mail.example.com TXT
    Result: DOES NOT EXIST
    Proof : VALID (NSEC)

---

## Q4: Key Lifecycle Analyzer

**File:** q4_key_lifecycle/key_lifecycle.py

**Description:**
Analyzes real-world DNSSEC key lifecycle. Detects ZSK/KSK
rollovers, DS mismatches, and RRSIG expiry issues.
Imports Q1 module.

**How to run:**

    cd q4_key_lifecycle
    python3 key_lifecycle.py <domain>

**Examples:**

    python3 key_lifecycle.py example.com
    python3 key_lifecycle.py cloudflare.com
    python3 key_lifecycle.py verisign.com

**Expected Output:**

    Domain: example.com
    Status: ZSK Rollover in Progress
    Observations:
      - Multiple ZSKs present
      - DS matches all KSKs -- chain of trust intact

---

## Q5: Tampering Detection (SEED Lab)

**File:** q5_tampering_demo/q5_validator.py

**Description:**
Demonstrates DNSSEC tamper detection using SEED Lab Docker
environment. Modifies an A record without re-signing and shows
the custom validator detects it.

**Prerequisites:**
- Docker Desktop must be running
- Rosetta emulation enabled in Docker Desktop settings

---

### Step 1: Build and start Docker containers

    cd q5_tampering_demo/Labsetup-arm
    cd base_image
    docker pull handsonsecurity/seed-server:bind-arm
    docker build -t seed-base-image-bind .
    cd ..
    docker-compose up --build -d
    docker ps

---

### Step 2: Configure DNSSEC on example.edu nameserver

Generate ZSK:

    docker exec -it example-edu-10.9.0.65 bash -c "cd /etc/bind && dnssec-keygen -a RSASHA256 -b 1024 example.edu"

Generate KSK:

    docker exec -it example-edu-10.9.0.65 bash -c "cd /etc/bind && dnssec-keygen -a RSASHA256 -b 2048 -f KSK example.edu"

Sign the zone:

    docker exec -it example-edu-10.9.0.65 bash -c "cd /etc/bind && dnssec-signzone -e 20501231000000 -S -o example.edu example.edu.db"

Update named.conf to use signed zone:

    docker exec -it example-edu-10.9.0.65 bash -c "echo 'zone \"example.edu\" { type master; file \"/etc/bind/example.edu.db.signed\"; };' > /etc/bind/named.conf.seedlabs && rndc reload"

---

### Step 3: Install Python dependencies in user container

Download packages on Mac:

    pip3 download "dnspython<2.7" --no-deps -d /tmp/dns_old
    pip3 download cryptography cffi pycparser --no-deps -d /tmp/crypto_deps --platform manylinux2014_aarch64 --python-version 38 --only-binary=:all:

Copy to container:

    docker cp /tmp/dns_old/. user-10.9.0.5:/home/
    docker cp /tmp/crypto_deps/. user-10.9.0.5:/home/

Install in container:

    docker exec -it user-10.9.0.5 bash -c "pip3 install /home/dnspython-2.6.1-py3-none-any.whl --force-reinstall"
    docker exec -it user-10.9.0.5 bash -c "rm /home/cryptography*macosx* && pip3 install /home/pycparser*.whl /home/cffi*.whl /home/cryptography*.whl --force-reinstall --no-deps"

---

### Step 4: Copy and run validator

    cd q5_tampering_demo
    docker cp q5_validator.py user-10.9.0.5:/home/
    docker exec -it user-10.9.0.5 bash -c "python3 /home/q5_validator.py"

Expected output: VALID with IP 1.2.3.5

---

### Step 5: Tamper with the A record

    docker exec -it example-edu-10.9.0.65 bash -c "sed -i 's/1.2.3.5/6.6.6.6/g' /etc/bind/example.edu.db.signed && rndc reload"
    docker exec -it local-dns-10.9.0.53 bash -c "rndc flush"

Query with dig (shows tampered IP, no ad flag):

    docker exec -it user-10.9.0.5 dig @10.9.0.53 www.example.edu A +dnssec

Run validator (should show INVALID):

    docker exec -it user-10.9.0.5 bash -c "python3 /home/q5_validator.py"

Expected output: INVALID, RRSIG verification failed

---

### Step 6: Restore original record

    docker exec -it example-edu-10.9.0.65 bash -c "sed -i 's/6.6.6.6/1.2.3.5/g' /etc/bind/example.edu.db.signed && rndc reload"

### Stop containers when done

    docker-compose down

---
