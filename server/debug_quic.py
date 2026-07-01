"""Debug QUIC SNI extraction on live traffic."""
import socket
import struct
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from quic_sni import _parse_quic_header, _decrypt_initial, extract_quic_sni, is_quic_initial

def debug_extract(data):
    """Extract with step-by-step debug."""
    header = _parse_quic_header(data)
    if header is None:
        print(f"  Header parse failed")
        return None
    
    print(f"  Header: ver=0x{header['version']:08x} dcid={header['dcid'].hex()[:16]} scid={header['scid'].hex()[:16]}")
    print(f"  pn_hint={header['pn_length_hint']} payload_len={header['payload_length']} header_end={header['header_end']} data_len={len(data)}")
    
    decrypted = _decrypt_initial(data, header)
    if decrypted is None:
        print(f"  DECRYPT FAILED")
        return None
    
    print(f"  Decrypted: {len(decrypted)} bytes, first=0x{decrypted[0]:02x}")
    return "OK"

# Capture from TUN
import subprocess
print("Capturing QUIC packets from tunnely0...")
proc = subprocess.Popen(
    ['sudo', 'tcpdump', '-i', 'tunnely0', '-c', '3', '-w', '-', 'udp', 'port', '443', '-s', '0'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE
)

import time
time.sleep(8)
proc.terminate()
data = proc.stdout.read()
stderr = proc.stderr.read().decode()
print(f"Captured {len(data)} bytes")
print(f"stderr: {stderr[:200]}")

# Parse pcap - raw IP packets
# Skip pcap global header (24 bytes) + per-packet header (16 bytes)
if len(data) > 40:
    # Find IP packets in pcap data
    pos = 24  # skip global header
    pkt_count = 0
    while pos + 16 <= len(data):
        # Per-packet header: ts_sec(4), ts_usec(4), incl_len(4), orig_len(4)
        incl_len = struct.unpack('<I', data[pos+8:pos+12])[0]
        pkt_start = pos + 16
        pkt_end = pkt_start + incl_len
        
        if pkt_end > len(data):
            break
        
        ip_pkt = data[pkt_start:pkt_end]
        
        # Parse IP header
        if len(ip_pkt) >= 28:  # IP(20) + UDP(8)
            ihl = (ip_pkt[0] & 0x0F) * 4
            proto = ip_pkt[9]
            dst_ip = f"{ip_pkt[16]}.{ip_pkt[17]}.{ip_pkt[18]}.{ip_pkt[19]}"
            
            if proto == 17:  # UDP
                udp_payload = ip_pkt[ihl + 8:]
                if len(udp_payload) > 0:
                    dst_port = (ip_pkt[ihl + 2] << 8) | ip_pkt[ihl + 3]
                    if dst_port == 443 and is_quic_initial(udp_payload):
                        print(f"\n=== QUIC Initial to {dst_ip}:443 ({len(udp_payload)} bytes) ===")
                        debug_extract(udp_payload)
                        pkt_count += 1
                        if pkt_count >= 3:
                            break
        
        pos = pkt_end
    
    if pkt_count == 0:
        print("No QUIC Initial packets found")
