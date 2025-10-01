"""
Ife Network Sniffer (Educational)

Safety & Legal
- Only run live captures on networks and machines for which you have explicit permission.
- Capturing others’ network traffic without consent may be illegal and unethical.
- Prefer using --pcap for learning, as it does not require elevated privileges.

Quick usage
  python sniffer.py --list-interfaces
  python sniffer.py --pcap path/to/file.pcap --filter tcp --count 50 --save-pcap
  python sniffer.py --live --interface "Wi-Fi" --count 100 --save-pcap

"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import socket
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---- Color output support ---------------------------------------------------
try:
    from colorama import Fore, Style, init as colorama_init
    _COLOR_BASELINE = True
except Exception:  # pragma: no cover
    class _F:
        RESET_ALL = ""; GREEN = ""; CYAN = ""; YELLOW = ""; RED = ""
    Fore = _F()  # type: ignore
    Style = _F()  # type: ignore
    def colorama_init(*args, **kwargs):  # type: ignore
        return None
    _COLOR_BASELINE = False

USE_COLOR = _COLOR_BASELINE

# ---- Scapy preferred, raw socket fallback ----------------------------------
try:
    from scapy.all import (
        sniff,
        rdpcap,
        wrpcap,
        PcapWriter,
        get_if_list,
        IP,
        IPv6,
        ARP,
        TCP,
        UDP,
        ICMP,
        Raw,
        Packet,
    )
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    Packet = object  # type: ignore

# ---- Utility: privilege check for live capture ------------------------------

def require_live_privileges_or_exit() -> None:
    if os.name == "nt":
        try:
            import ctypes  # type: ignore
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                print("ERROR: Live capture requires Administrator privileges on Windows.")
                sys.exit(1)
        except Exception:
            print("WARNING: Unable to verify Administrator privileges on Windows.")
    else:
        if os.geteuid() != 0:  # type: ignore[attr-defined]
            print("ERROR: Live capture requires root privileges on this OS.")
            sys.exit(1)

# ---- Payload formatting -----------------------------------------------------

def format_payload(payload: bytes, truncate: int) -> str:
    view = payload[: max(0, truncate)]
    hex_str = " ".join(f"{b:02x}" for b in view)
    ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in view)
    suffix = " ..." if len(payload) > len(view) else ""
    return f"HEX: {hex_str}{suffix}\nASCII: {ascii_str}{suffix}"

# ---- Simple human summary ---------------------------------------------------

def eli12(pkt: Packet) -> str:
    try:
        if hasattr(pkt, "haslayer"):
            if pkt.haslayer(TCP):
                return "TCP: likely web/app data or connection signaling."
            if pkt.haslayer(UDP):
                return "UDP: quick messages (e.g., DNS, streaming)."
            if pkt.haslayer(ICMP):
                return "ICMP: network checks like ping."
            if pkt.haslayer(ARP):
                return "ARP: local network address resolution."
        return "Other protocol traffic."
    except Exception:
        return "Packet summary unavailable."

# ---- Display one packet (Scapy path) ---------------------------------------

def show_packet(pkt: Packet, no_payload: bool, truncate: int, stats: Dict[str, int]) -> None:
    ts = dt.datetime.fromtimestamp(getattr(pkt, "time", dt.datetime.now().timestamp())).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    l3 = "Unknown"; src = ""; dst = ""
    if hasattr(pkt, "haslayer") and pkt.haslayer(IP):
        l3, src, dst = "IPv4", pkt[IP].src, pkt[IP].dst
    elif hasattr(pkt, "haslayer") and pkt.haslayer(IPv6):
        l3, src, dst = "IPv6", pkt[IPv6].src, pkt[IPv6].dst
    elif hasattr(pkt, "haslayer") and pkt.haslayer(ARP):
        l3, src, dst = "ARP", pkt[ARP].psrc, pkt[ARP].pdst

    l4 = "Other"; sport = ""; dport = ""
    if hasattr(pkt, "haslayer") and pkt.haslayer(TCP):
        l4, sport, dport = "TCP", str(pkt[TCP].sport), str(pkt[TCP].dport)
    elif hasattr(pkt, "haslayer") and pkt.haslayer(UDP):
        l4, sport, dport = "UDP", str(pkt[UDP].sport), str(pkt[UDP].dport)
    elif hasattr(pkt, "haslayer") and pkt.haslayer(ICMP):
        l4 = "ICMP"

    # Update stats
    stats["total"] = stats.get("total", 0) + 1
    stats[l3] = stats.get(l3, 0) + 1
    stats[l4] = stats.get(l4, 0) + 1

    length = len(pkt) if hasattr(pkt, "__len__") else 0
    summary = pkt.summary() if hasattr(pkt, "summary") else ""

    if USE_COLOR:
        src_col = f"{Fore.GREEN}{src}{Style.RESET_ALL}" if src else src
        dst_col = f"{Fore.CYAN}{dst}{Style.RESET_ALL}" if dst else dst
    else:
        src_col, dst_col = src, dst

    print(f"{ts} | {src_col} -> {dst_col} | L3: {l3} | L4: {l4} | Sport: {sport} | Dport: {dport} | Len: {length}")
    print(f"Summary: {summary} | {eli12(pkt)}")

    if not no_payload and hasattr(pkt, "haslayer") and pkt.haslayer(Raw):
        try:
            data = bytes(pkt[Raw].load)
            if data:
                print(format_payload(data, truncate))
        except Exception:
            pass
    print("-" * 80)

# ---- Simple protocol filter for Scapy packets -------------------------------

def simple_filter(pkt: Packet, filt: Optional[str]) -> bool:
    if not filt:
        return True
    f = filt.lower()
    try:
        if pkt.haslayer(TCP) and f == "tcp":
            return True
        if pkt.haslayer(UDP) and f == "udp":
            return True
        if pkt.haslayer(ICMP) and f == "icmp":
            return True
        if pkt.haslayer(ARP) and f == "arp":
            return True
        if pkt.haslayer(IP) and f == "ip":
            return True
        if pkt.haslayer(IPv6) and f == "ipv6":
            return True
        return False
    except Exception:
        return True

# ---- Raw-socket helpers (fallback) ------------------------------------------

def parse_ethernet_frame(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 14:
        return (0, b"")
    _, _, proto = struct.unpack("!6s6sH", data[:14])
    return (proto, data[14:])


def parse_ipv4_packet(data: bytes) -> Tuple[str, str, int]:
    if len(data) < 20:
        return ("", "", -1)
    ver_ihl = data[0]
    version = ver_ihl >> 4
    if version != 4:
        return ("", "", -1)
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    proto_num = data[9]
    return (src_ip, dst_ip, proto_num)

# ---- PCAP saving helpers ----------------------------------------------------

def resolve_capture_path(base_dir: Path, user_path: Optional[str]) -> Path:
    captures_dir = base_dir / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)
    if user_path and user_path.strip():
        p = Path(user_path)
        if not p.is_absolute():
            p = captures_dir / p
        return p
    # Automatic file name
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return captures_dir / f"capture-{ts}.pcap"

# ---- Capture functions ------------------------------------------------------

def scapy_read_pcap(path: str, count: Optional[int], filt: Optional[str], no_payload: bool, truncate: int, save_path: Optional[Path], stats: Dict[str, int]) -> None:
    print(f"[INFO] Reading PCAP: {path}")
    packets = rdpcap(path)
    writer: Optional[PcapWriter] = None
    kept = []
    for pkt in packets:
        if filt and not simple_filter(pkt, filt):
            continue
        show_packet(pkt, no_payload, truncate, stats)
        kept.append(pkt)
        if save_path and writer is None:
            try:
                writer = PcapWriter(str(save_path), append=False, sync=True)
                print(f"[INFO] Creating PCAP and streaming to: {save_path}")
            except Exception as e:
                print(f"[WARN] Could not create PCAP writer: {e}")
                writer = None
        if writer is not None:
            try:
                writer.write(pkt)
            except Exception:
                pass
        if count is not None and len(kept) >= count:
            break
    if writer is not None:
        try:
            writer.close()
        except Exception:
            pass
    elif save_path and kept:
        # Fallback one-shot save if writer failed
        try:
            wrpcap(str(save_path), kept)
            print(f"[INFO] Saved {len(kept)} packet(s) to {save_path}")
        except Exception as e:
            print(f"[WARN] Failed to save pcap: {e}")
    elif save_path and not kept:
        print("[INFO] No packets matched filter/count; no PCAP file was created.")


def scapy_live_capture(interface: str, count: Optional[int], filt: Optional[str], no_payload: bool, truncate: int, save_path: Optional[Path], stats: Dict[str, int]) -> None:
    require_live_privileges_or_exit()
    print(f"[INFO] Live capture on {interface} (Scapy)")
    kept: List[Packet] = []
    writer: Optional[PcapWriter] = None

    def _cb(p: Packet):
        if simple_filter(p, filt):
            show_packet(p, no_payload, truncate, stats)
            kept.append(p)
            nonlocal writer
            if save_path and writer is None:
                try:
                    writer = PcapWriter(str(save_path), append=False, sync=True)
                    print(f"[INFO] Creating PCAP and streaming to: {save_path}")
                except Exception as e:
                    print(f"[WARN] Could not create PCAP writer: {e}")
                    writer = None
            if writer is not None:
                try:
                    writer.write(p)
                except Exception:
                    pass

    sniff(iface=interface, count=count, filter=filt, prn=_cb)
    if writer is not None:
        try:
            writer.close()
        except Exception:
            pass
    elif save_path and not kept:
        print("[INFO] No packets matched filter/count; no PCAP file was created.")


def rawsocket_live_capture(interface: str, count: Optional[int], stats: Dict[str, int]) -> None:
    """Very basic IPv4-only fallback using raw sockets (metadata only)."""
    require_live_privileges_or_exit()
    print(f"[INFO] Live capture on {interface} (raw socket fallback)")

    if os.name == "nt":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((interface, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))

    c = 0
    try:
        while count is None or c < count:
            raw, _ = s.recvfrom(65535)
            eth_proto, payload = parse_ethernet_frame(raw) if os.name != "nt" else (0x0800, raw)
            if eth_proto == 0x0800:  # IPv4
                src, dst, pnum = parse_ipv4_packet(payload)
                l4 = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(pnum, str(pnum))
                stats["total"] = stats.get("total", 0) + 1
                stats["IPv4"] = stats.get("IPv4", 0) + 1
                stats[l4] = stats.get(l4, 0) + 1
                now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                if USE_COLOR:
                    src_col = f"{Fore.GREEN}{src}{Style.RESET_ALL}" if src else src
                    dst_col = f"{Fore.CYAN}{dst}{Style.RESET_ALL}" if dst else dst
                else:
                    src_col, dst_col = src, dst
                print(f"{now} | {src_col} -> {dst_col} | L3: IPv4 | L4: {l4} | Len: {len(raw)}")
                print("Summary: Raw-socket fallback (headers only)")
                print("-" * 80)
                c += 1
    finally:
        try:
            if os.name == "nt":
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        s.close()

# ---- CLI -------------------------------------------------------------------

def list_interfaces() -> None:
    if not SCAPY_AVAILABLE:
        print("Scapy is required to list interfaces. Install with: python -m pip install scapy")
        return
    try:
        interfaces = get_if_list()
        print("Available interfaces:")
        for name in interfaces:
            print(f"  - {name}")
    except Exception as e:
        print(f"Failed to list interfaces: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Ife Network Sniffer (Educational)")

    mode = parser.add_mutually_exclusive_group(required=False)
    mode.add_argument("--pcap", type=str, help="Read packets from a pcap file (Scapy)")
    mode.add_argument("--live", action="store_true", help="Capture live packets (requires admin/root)")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces and exit")

    parser.add_argument("--interface", type=str, help="Network interface for live capture")
    parser.add_argument("--count", type=int, help="Max number of packets to process")
    parser.add_argument("--filter", type=str, help="Filter: tcp|udp|icmp|arp|ip|ipv6 (simple)")
    parser.add_argument("--no-payload", action="store_true", help="Suppress payload printout")
    parser.add_argument("--truncate", type=int, default=64, help="Payload preview bytes (default 64)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in output")
    parser.add_argument("--force-color", action="store_true", help="Force-enable ANSI colors")
    parser.add_argument("--save-pcap", nargs="?", const="", default=None, help="Save displayed packets to captures/ (optional file name)")

    args = parser.parse_args()

    # Init color output
    global USE_COLOR
    if args.no_color:
        USE_COLOR = False
    else:
        # Enable colors if TTY or explicitly requested
        if args.force_color or sys.stdout.isatty():
            try:
                colorama_init(autoreset=True, convert=True, strip=False)
                USE_COLOR = True
            except Exception:
                USE_COLOR = False
        else:
            USE_COLOR = False

    print("Safety note: Only run live captures on networks and machines for which you have explicit permission.")
    print("Prefer analyzing recorded traffic with --pcap when learning.")

    # List interfaces
    if args.list_interfaces:
        list_interfaces()
        return

    # Decide on save path (project-relative captures/)
    base_dir = Path(__file__).resolve().parent
    save_path: Optional[Path] = None
    if args.save_pcap is not None:
        save_path = resolve_capture_path(base_dir, args.save_pcap)
        print(f"[INFO] PCAP output will be saved to: {save_path}")

    # Packet stats
    stats: Dict[str, int] = {}

    # Modes
    if args.pcap:
        if not SCAPY_AVAILABLE:
            print("Scapy is required for --pcap mode. Install with: python -m pip install scapy")
            sys.exit(1)
        scapy_read_pcap(args.pcap, args.count, args.filter, args.no_payload, args.truncate, save_path, stats)
    elif args.live:
        if args.interface is None:
            print("--interface is required for live capture")
            sys.exit(1)
        if SCAPY_AVAILABLE:
            try:
                scapy_live_capture(args.interface, args.count, args.filter, args.no_payload, args.truncate, save_path, stats)
            except Exception as e:
                print(f"[WARN] Scapy live capture failed ({e}). Falling back to raw sockets (no PCAP saving)...")
                rawsocket_live_capture(args.interface, args.count, stats)
        else:
            print("[INFO] Scapy not available. Using raw-socket fallback (no PCAP saving)...")
            rawsocket_live_capture(args.interface, args.count, stats)
    else:
        parser.print_help()
        return

    # Print final stats
    if stats:
        print("\nCapture summary:")
        for k in sorted(stats.keys()):
            print(f"  {k}: {stats[k]}")


if __name__ == "__main__":
    main()
