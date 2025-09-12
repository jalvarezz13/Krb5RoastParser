# Krb5RoastParser

## 📑 Table of Contents

- [❓ What is Krb5RoastParser?](#-what-is-krb5roastparser)
- [⭐ Features](#-features)
- [⚙️ Installation](#%EF%B8%8F-installation)
- [▶️ Execution](#%EF%B8%8F-execution)
- [📈 Post Execution](#-post-execution)
- [📜 License](#-license)

## ❓ What is **Krb5RoastParser**?

**Krb5RoastParser** is a tool designed to parse Kerberos authentication packets (AS-REQ, AS-REP and TGS-REP) from `.pcap` files and generate password-cracking-compatible hashes for security testing. By leveraging `tshark`, Krb5RoastParser extracts necessary details from Kerberos packets, providing hash formats ready for tools like Hashcat.

## ⭐ Features

- Parse AS-REQ, AS-REP and TGS-REP packets from `.pcap` files.
- Generate hashes compatible with Hashcat for password-cracking.
- Easy to extend for future hash formats (e.g., `john`).

## ⚙️ Installation

### Prerequisites

Ensure you have:

- Python 3.7 or higher
- `tshark` installed and accessible in your PATH

To install `tshark` (if not already installed):

```bash
# On Debian/Ubuntu
sudo apt update
sudo apt install tshark -y

# On macOS (using Homebrew)
brew install wireshark

# On Windows is included in the Wireshark installation
```

### Clone the Repository

```bash
git clone https://github.com/jalvarezz13/Krb5RoastParser.git
cd Krb5RoastParser
```

## ▶️ Execution

To run Krb5RoastParser, use the following syntax:

```bash
python krb5_roast_parser.py <pcap_file> <as_req/as_rep/tgs_rep>
```

- `<pcap_file>`: The path to the `.pcap` file containing Kerberos packets.
- `<as_req/as_rep>`: Specify the type of Kerberos packet to parse.
  - Use `as_req` for AS-REQ packets
  - Use `as_rep` for AS-REP packets
  - Use `tgs_rep` for TGS-REP packets

### Example Commands

Parse AS-REQ packets:

```bash
python krb5_roast_parser.py sample.pcap as_req
```

Parse AS-REP packets:

```bash
python krb5_roast_parser.py sample.pcap as_rep
```

Parse TGS-REP packets:

```bash
python krb5_roast_parser.py sample.pcap tgs_rep
```

### Output

- For `as_req`: The output will be in `$krb5pa$18$...` format.
- For `as_rep`: The output will be in `$krb5asrep$23$...` format.
- For `tgs_rep`: The output will be in `$krb5tgs$23$...` format.

These outputs are compatible with Hashcat hash modes.

> [!NOTE]  
> By the moment, the tool only supports these hash formats. If you need support for other hash formats, feel free to open an issue or submit a pull request.

## 🔓 Post Execution

Once you have the generated hashes, you can use Hashcat to attempt to crack them.

### Cracking AS-REQ Hashes

For AS-REQ hashes, use Hashcat mode `19900`:

```bash
hashcat -m 19900 <hashfile> <wordlist>
```

### Cracking AS-REP Hashes

For AS-REP hashes, use Hashcat mode `18200`:

```bash
hashcat -m 18200 <hashfile> <wordlist>
```

### Cracking TGS-REP Hashes

For TGS-REP hashes, use Hashcat mode `13100`:

```bash
hashcat -m 13100 <hashfile> <wordlist>
```

Replace `<hashfile>` with the file containing the extracted hashes and `<wordlist>` with your wordlist file.

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for more information.
