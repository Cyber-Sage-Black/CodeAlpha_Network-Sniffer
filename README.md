# Ife Network Sniffer

A friendly, beginner‑oriented Python tool that lets you peek at network packets in a safe, simple way. It’s built for learning and lab use under the supervision of CodeAlpha.

> Safety first: Only capture traffic on networks and machines where you have explicit permission. Capturing others’ traffic without consent may be illegal and unethical. Prefer PCAP analysis when learning.

## What this tool does (in plain English)
- **Reads packets** from a saved capture file (PCAP) or **sniffs live** traffic (admin/root required for live).
- Shows useful **metadata** about each packet: time, who sent it (source IP), who got it (destination IP), what protocol was used (IPv4/IPv6/ARP + TCP/UDP/ICMP), ports, and size.
- Provides a short, **human explanation** for common protocols (e.g., “ICMP = ping”).
- **Color highlights** the source IP in green and destination IP in cyan to make traffic direction easier to see.
- Lets you **limit or hide payloads** to avoid printing sensitive data.
- Can **save the packets you viewed** to a new PCAP file for later analysis in Wireshark.

## Folder layout
```
Ife Network Sniffer/
├─ sniffer.py        # the main program
├─ README.md         # this file
└─ captures/         # PCAPs you save here (auto‑created)
```

## Requirements
- Python 3.10+
- Python packages:
  - scapy (for PCAP reading and full‑feature sniffing)
  - colorama (for colored terminal text)

Install them with:
```powershell
python -m pip install -r requirements.txt
```
(If `requirements.txt` isn’t next to this folder, install manually: `python -m pip install scapy colorama`)

## Get your bearings
- **List your network interfaces** (so you know what name to use for live capture):
  ```powershell
  python sniffer.py --list-interfaces
  ```
- If you see names like `Wi-Fi`, `Ethernet`, `wlan0`, or `eth0`, that’s what you pass to `--interface`.

## Common ways to run
- **Read a PCAP (safest way to learn):**
  ```powershell
  python sniffer.py --pcap "C:\path\to\traffic.pcap" --filter tcp --count 50 --truncate 64 --save-pcap
  ```
  What this does:
  - Reads packets from the file.
  - Only shows TCP packets (`--filter tcp`).
  - Stops after 50 packets (`--count 50`).
  - Prints up to 64 bytes of payload (`--truncate 64`).
  - Saves the shown packets to a new file under `captures/` (`--save-pcap`).

- **Live capture (authorized use only):**
  ```powershell
  # Windows: run PowerShell as Administrator; install Npcap for best results
  python sniffer.py --live --interface "Wi-Fi" --count 100 --save-pcap

  # Linux/macOS: run as root
  sudo python3 sniffer.py --live --interface eth0 --filter udp
  ```

### Where your saved files go
- When you use `--save-pcap`, the program creates a file inside the `captures/` folder next to `sniffer.py`.
- If you don’t give a name, it uses a timestamp like `capture-YYYYMMDD-HHMMSS.pcap`.
- The file is written while packets arrive (streaming), so you’ll see it appear during the run.

Example folder path on your machine:
```
c:\Users\HomePC\Documents\WINSURF\Ife Network Sniffer\captures\
```

## Options (plain language)
- `--pcap <file>`: read from a PCAP file (great for learning, no admin).
- `--live`: capture in real time (requires admin/root). Use `--interface` with this.
- `--interface <name>`: which adapter to listen on (see `--list-interfaces`).
- `--count <N>`: stop after N packets.
- `--filter <proto>`: show only a protocol (tcp, udp, icmp, arp, ip, ipv6).
- `--no-payload`: don’t print any payload bytes.
- `--truncate <N>`: how many payload bytes to print (default 64; hex + ASCII preview).
- `--no-color`: turn off colors if your terminal doesn’t support them.
- `--force-color`: force colors on (handy in some terminals).
- `--save-pcap [name]`: save the packets you see to `captures/<name or timestamp>.pcap`.
- `--list-interfaces`: print available interfaces and exit.

Tip: If colors don’t show in your terminal, add `--force-color` or try Windows Terminal/PowerShell.

## Interpreting what you see
- **TCP** to port 80/443: probably web traffic (HTTP/HTTPS).
- **UDP** to port 53: likely DNS (name lookups).
- **ICMP**: things like `ping` and other network checks.
- **ARP**: local devices asking “who has this IP?”

## Troubleshooting
- **No colors?** Try Windows Terminal or PowerShell, and avoid redirecting output. You can also use `--force-color`.
- **PCAP saving didn’t work?** Make sure Scapy is installed; the raw‑socket fallback can’t save PCAPs.
- **Live capture not working on Windows?** Install Npcap (https://nmap.org/npcap/) and run PowerShell as Administrator.
- **Still nothing captured?** Double‑check the interface name and generate some traffic (e.g., open a website or `ping 8.8.8.8`).

## Ethics reminder
Always follow the rules. Only sniff traffic you’re allowed to see. Stick to PCAP files for learning if you’re unsure.

## License
Educational use. Add a license file (e.g., MIT) if publishing to GitHub.
