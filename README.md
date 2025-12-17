# network-scannr

#!/usr/bin/env python3
"""
Network Scanner from Scratch
Author: [Your Name]
Date: $(date)
Description: A tool to scan open ports using raw TCP packets without external libraries.
"""

import sys
import struct
import socket
import time

def checksum(data):
    """
    Compute checksum for a packet to ensure integrity.
    Input:
         Bytes to compute checksum for
    Output:
        checksum: 16-bit one's complement checksum
    """
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i] << 8) + data[i + 1]
    if n:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xFFFF
    return s

def create_syn_packet(src_ip, dst_ip, dst_port):
    """
    Build a TCP SYN packet manually (IP + TCP headers).
    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        dst_port: Target port number
    Returns:
        packet: Full raw packet (IP header + TCP header)
    """
    # ===== 1. IP Header (20 bytes) =====
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 40  # IP (20) + TCP (20)
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s',
                           ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
                           ip_frag_off, ip_ttl, ip_proto, ip_check,
                           ip_saddr, ip_daddr)

    # ===== 2. TCP Header (20 bytes) =====
    tcp_source = 12345
    tcp_dest = dst_port
    tcp_seq = 0
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_flags = 0x02  # SYN flag
    tcp_window = socket.htons(65535)
    tcp_check = 0
    tcp_urg_ptr = 0
    tcp_offset_res = (tcp_doff << 4) + 0

    tcp_header = struct.pack('!HHLLBBHHH',
                            tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                            tcp_offset_res, tcp_flags, tcp_window,
                            tcp_check, tcp_urg_ptr)

    # ===== 3. Compute TCP Checksum =====
    placeholder = 0
    tcp_length = len(tcp_header)
    psh = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, placeholder, ip_proto, tcp_length)
    psh = psh + tcp_header
    tcp_checksum = checksum(psh)

    # ===== 4. Rebuild TCP Header with Correct Checksum =====
    tcp_header = struct.pack('!HHLLBBHHH',
                            tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                            tcp_offset_res, tcp_flags, tcp_window,
                            tcp_checksum, tcp_urg_ptr)

    return ip_header + tcp_header

def listen_for_synack(target_ip, target_port):
    """
    Listen for a SYN-ACK response from the target.
    Returns:
        True if SYN-ACK received (port is open)
        False if timeout or no response (port closed)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
            s.bind((target_ip, 0))
            s.settimeout(2)
            packet, addr = s.recvfrom(1024)
            tcp_header = packet[20:40]
            flags = struct.unpack('!H', tcp_header[12:14])[0] >> 8
            if flags == 0x12:  # SYN+ACK = 0x12
                return True
            return False
    except socket.timeout:
        return False
    except Exception as e:
        print(f"[ERROR] Failed to listen: {e}")
        return False

def get_local_ip(target_ip):
    """
    Get the local IP address by connecting to the target.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target_ip, 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"[ERROR] Could not get local IP: {e}")
        sys.exit(1)

def main():
    """
    Main entry point of the scanner.
    Usage: sudo python3 scanner.py <target_ip> <port>
    """
    if len(sys.argv) != 3:
        print("Usage: sudo python3 scanner.py <target_ip> <port>")
        print("Example: sudo python3 scanner.py 127.0.0.1 22")
        sys.exit(1)

    target_ip = sys.argv[1]
    port = int(sys.argv[2])

    if port < 1 or port > 65535:
        print("[ERROR] Invalid port number. Must be between 1 and 65535.")
        sys.exit(1)

    print(f"[*] Scanning port {port} on {target_ip}...")
    src_ip = get_local_ip(target_ip)
    print(f"[*] Local IP: {src_ip}")

    try:
        packet = create_syn_packet(src_ip, target_ip, port)
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
            s.sendto(packet, (target_ip, 0))
        print(f"[+] SYN packet sent to {target_ip}:{port}")

        time.sleep(0.5)

        if listen_for_synack(target_ip, port):
            print(f"\033[92m[OPEN]\033[0m Port {port} is open on {target_ip}!")
        else:
            print(f"\033[91m[CLOSED]\033[0m Port {port} is closed on {target_ip}")

    except PermissionError:
        print("[ERROR] Root privileges required. Run with sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
