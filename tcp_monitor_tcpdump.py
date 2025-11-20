#!/usr/bin/env python3
import subprocess
import sys
import re
from datetime import datetime

def monitor_with_tcpdump(target_ip="192.168.240.1", target_port=10443):
    """Use tcpdump to monitor bidirectional traffic"""
    print(f"Monitoring TCP traffic: {target_ip}:{target_port} (bidirectional)")
    print("=" * 80)
    
    # Build tcpdump command
    # -i any: capture on all interfaces
    # -n: don't resolve hostnames
    # -X: print packet data in hex and ASCII
    # -s 0: capture full packets
    # -l: line buffered output
    # -D: list interfaces (for debugging)
    cmd = [
        "sudo", "tcpdump",
        "-i", "any",
        "-n",
        "-X",
        "-s", "0",
        "-l",
        f"host {target_ip} and port {target_port}"
    ]
    
    try:
        # Start tcpdump process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        
        current_packet = []
        is_hex_section = False
        last_packet_hash = None
        
        for line in process.stdout:
            # Detect packet header line (timestamp)
            if re.match(r'^\d{2}:\d{2}:\d{2}\.\d+', line):
                # Process previous packet if exists
                if current_packet:
                    packet_hash = process_packet(current_packet, target_ip, target_port, last_packet_hash)
                    if packet_hash:
                        last_packet_hash = packet_hash
                current_packet = [line.strip()]
                is_hex_section = False
            # Detect hex dump section
            elif line.startswith('\t0x'):
                is_hex_section = True
                current_packet.append(line.strip())
            # Continue collecting packet data
            elif current_packet:
                current_packet.append(line.strip())
                
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        process.terminate()
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure tcpdump is installed: sudo apt-get install tcpdump")

def process_packet(lines, target_ip, target_port, last_packet_hash=None):
    """Process and display packet information"""
    if not lines:
        return None
    
    header_line = lines[0]
    
    # Parse header line for direction and basic info
    # Example: "13:30:53.581234 IP 192.168.240.112.51240 > 192.168.240.1.10443: Flags [P.], seq 1:439, ack 1, win 502, length 438"
    
    # Extract timestamp (without microseconds for deduplication)
    timestamp_match = re.match(r'^(\d{2}:\d{2}:\d{2})\.(\d+)', header_line)
    if timestamp_match:
        timestamp_base = timestamp_match.group(1)
        timestamp_micro = timestamp_match.group(2)[:3]  # First 3 digits of microseconds
        timestamp = f"{timestamp_base}.{timestamp_micro}"
    else:
        timestamp = "??:??:??"
        timestamp_base = ""
    
    # Determine direction
    if f"> {target_ip}.{target_port}" in header_line:
        direction = ">>> CLIENT -> SERVER"
        arrow = ">>>"
    elif f"{target_ip}.{target_port} >" in header_line:
        direction = "<<< SERVER -> CLIENT"
        arrow = "<<<"
    else:
        return None  # Skip if not our target
    
    # Extract flags
    flags_match = re.search(r'Flags \[([^\]]+)\]', header_line)
    flags = flags_match.group(1) if flags_match else ""
    
    # Extract length
    length_match = re.search(r'length (\d+)', header_line)
    length = length_match.group(1) if length_match else "0"
    
    # Extract source and destination
    conn_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)', header_line)
    if conn_match:
        src_ip = conn_match.group(1)
        src_port = conn_match.group(2)
        dst_ip = conn_match.group(3)
        dst_port = conn_match.group(4)
    else:
        src_ip = src_port = dst_ip = dst_port = "?"
    
    # Skip packets with no data (control packets like FIN, RST, pure ACKs)
    if length == "0":
        return None
    
    # Create packet hash for deduplication (based on timestamp prefix, IPs, ports, flags, length)
    packet_hash = f"{timestamp_base}_{src_ip}:{src_port}_{dst_ip}:{dst_port}_{flags}_{length}"
    
    # Skip if this is a duplicate packet (same within microseconds)
    if packet_hash == last_packet_hash:
        return packet_hash
    
    # Extract hex data
    hex_data = []
    for line in lines[1:]:
        if line.startswith('\t0x'):
            # Extract hex bytes from tcpdump format
            # Example: "\t0x0000:  4500 01b6 5e2f 4000 4006 2d3f c0a8 f070"
            hex_part = re.search(r'0x[0-9a-f]+:\s+([0-9a-f\s]+)', line)
            if hex_part:
                # Remove spaces and convert to space-separated bytes
                hex_str = hex_part.group(1).replace(' ', '')
                hex_bytes = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2) if i+1 < len(hex_str))
                hex_data.append(hex_bytes)
    
    # Display packet info
    print(f"\n[{timestamp}] {direction}")
    print(f"  {src_ip}:{src_port} → {dst_ip}:{dst_port}")
    print(f"  Flags: [{flags}] | Length: {length}")
    
    if hex_data and length != "0":
        full_hex = ' '.join(hex_data)
        if len(full_hex) > 200:
            print(f"  Data: {full_hex[:200]}... ({length} bytes total)")
        else:
            print(f"  Data: {full_hex}")
    
    print("-" * 80)
    
    return packet_hash

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            if len(sys.argv) >= 3:
                ip = sys.argv[1]
                port = int(sys.argv[2])
                monitor_with_tcpdump(ip, port)
            else:
                print("Usage: python3 tcp_monitor_tcpdump.py [ip] [port]")
                print("Default: python3 tcp_monitor_tcpdump.py 192.168.240.1 10443")
                sys.exit(1)
        except ValueError:
            print("Error: Port must be a number")
            sys.exit(1)
    else:
        monitor_with_tcpdump()