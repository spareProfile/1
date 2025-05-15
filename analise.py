import sys
from collections import Counter, defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

def analyze_pcap(filename):
    packets = rdpcap(filename)
    total_packets = len(packets)
    ip_counter = Counter()
    proto_counter = Counter()
    ports_counter = Counter()
    
    # Data structures for advanced analysis
    tcp_sessions = defaultdict(list)
    tcp_retransmissions = 0
    tcp_out_of_order = 0
    tcp_sessions_stats = {}
    
    # Track ICMP errors which can indicate packet loss
    icmp_errors = Counter()
    
    # Track timing information
    packet_timestamps = {}
    rtt_values = []
    
    # New counters for IP pairs, TTL values, and packet size
    ip_pairs_counter = Counter()
    ip_ttl_counter = Counter()
    packet_size_sum = 0
    
    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            ip_counter.update([src, dst])
            proto = pkt[IP].proto
            proto_counter.update([proto])
            
            ip_pairs_counter.update([(src, dst)])
            ip_ttl_counter.update([pkt[IP].ttl])
            
            if TCP in pkt:
                ports_counter.update([pkt[TCP].sport, pkt[TCP].dport])
                
                # Create a session key for tracking TCP conversations
                session_key = (src, pkt[TCP].sport, dst, pkt[TCP].dport)
                reverse_session_key = (dst, pkt[TCP].dport, src, pkt[TCP].sport)
                
                # Check for retransmissions
                if session_key in tcp_sessions or reverse_session_key in tcp_sessions:
                    proper_key = session_key if session_key in tcp_sessions else reverse_session_key
                    
                    # Check if this sequence was already seen
                    if pkt[TCP].seq in [p[TCP].seq for p in tcp_sessions[proper_key]]:
                        tcp_retransmissions += 1
                    
                    # Check for out-of-order packets
                    if tcp_sessions[proper_key] and pkt[TCP].seq < tcp_sessions[proper_key][-1][TCP].seq:
                        tcp_out_of_order += 1
                    
                    # Calculate RTT if this is an ACK for a SYN
                    if pkt[TCP].flags & 0x10 and proper_key in packet_timestamps:  # ACK flag
                        if proper_key in packet_timestamps:
                            rtt = pkt.time - packet_timestamps[proper_key]
                            rtt_values.append(rtt)
                
                # Store packet in session history
                tcp_sessions[session_key].append(pkt)
                
                # Keep track of SYN packets timestamps for RTT calculation
                if pkt[TCP].flags & 0x02:  # SYN flag
                    packet_timestamps[session_key] = pkt.time
                
                # Track session establishment and teardown
                if session_key not in tcp_sessions_stats:
                    tcp_sessions_stats[session_key] = {'syn': 0, 'syn_ack': 0, 'fin': 0, 'rst': 0}
                
                flags = pkt[TCP].flags
                if flags & 0x02:  # SYN
                    tcp_sessions_stats[session_key]['syn'] += 1
                if flags & 0x12 == 0x12:  # SYN-ACK
                    tcp_sessions_stats[session_key]['syn_ack'] += 1
                if flags & 0x01:  # FIN
                    tcp_sessions_stats[session_key]['fin'] += 1
                if flags & 0x04:  # RST
                    tcp_sessions_stats[session_key]['rst'] += 1
                    
            elif UDP in pkt:
                ports_counter.update([pkt[UDP].sport, pkt[UDP].dport])
            
            # Track ICMP errors which can indicate packet loss
            if ICMP in pkt:
                if pkt[ICMP].type == 3:  # Destination unreachable
                    icmp_errors.update(['Destination unreachable'])
                elif pkt[ICMP].type == 11:  # Time exceeded
                    icmp_errors.update(['Time exceeded'])
        
        packet_size_sum += len(pkt)

    # Calculate TCP session statistics
    complete_sessions = 0
    incomplete_sessions = 0
    reset_sessions = 0
    
    for session, stats in tcp_sessions_stats.items():
        if stats['syn'] > 0 and stats['syn_ack'] > 0 and stats['fin'] >= 2:
            complete_sessions += 1
        elif stats['rst'] > 0:
            reset_sessions += 1
        elif stats['syn'] > 0:
            incomplete_sessions += 1
    
    # Basic packet statistics
    print(f"Total packets: {total_packets}")
    
    print("\nTop 5 IP addresses:")
    for ip, count in ip_counter.most_common(5):
        print(f"{ip}: {count} packets")

    print("\nProtocol usage:")
    for proto, count in proto_counter.items():
        name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
        print(f"{name}: {count} packets")

    print("\nTop 5 ports:")
    for port, count in ports_counter.most_common(5):
        print(f"Port {port}: {count} packets")
    
    # Advanced analysis results
    print("\n--- DETAILED NETWORK ANALYSIS ---")
    
    # TCP Sessions analysis
    print(f"\nTCP Sessions: {len(tcp_sessions)}")
    print(f"  Complete sessions: {complete_sessions}")
    print(f"  Incomplete sessions: {incomplete_sessions}")
    print(f"  Reset sessions: {reset_sessions}")
    
    # Packet loss indicators
    print("\nPacket Loss Indicators:")
    print(f"  TCP Retransmissions: {tcp_retransmissions}")
    print(f"  Out-of-order packets: {tcp_out_of_order}")
    
    if icmp_errors:
        print("\nICMP Errors (potential packet loss):")
        for error, count in icmp_errors.items():
            print(f"  {error}: {count}")
    
    # RTT Analysis
    if rtt_values:
        avg_rtt = sum(rtt_values) / len(rtt_values)
        min_rtt = min(rtt_values)
        max_rtt = max(rtt_values)
        print("\nRound-Trip Time (RTT) Statistics:")
        print(f"  Minimum RTT: {min_rtt:.6f} seconds")
        print(f"  Average RTT: {avg_rtt:.6f} seconds")
        print(f"  Maximum RTT: {max_rtt:.6f} seconds")
    
    # Packet loss percentage estimate based on retransmissions
    if proto_counter.get(6, 0) > 0:  # If we have TCP packets
        tcp_total = proto_counter.get(6, 0)
        packet_loss_percentage = (tcp_retransmissions / tcp_total) * 100 if tcp_total > 0 else 0
        print(f"\nEstimated TCP packet loss: {packet_loss_percentage:.2f}%")
        print(f"  Lost packets (retransmissions): {tcp_retransmissions}")
        print(f"  Successfully delivered packets: {tcp_total - tcp_retransmissions}")
    
    # New analytics
    avg_packet_size = packet_size_sum / total_packets if total_packets else 0
    print(f"\nAverage Packet Size: {avg_packet_size:.2f} bytes")

    print("\nTop 5 IP pairs:")
    for pair, count in ip_pairs_counter.most_common(5):
        print(f"{pair[0]} -> {pair[1]}: {count} packets")

    print("\nTop 5 TTL values:")
    for value, count in ip_ttl_counter.most_common(5):
        print(f"TTL {value}: {count} packets")

if __name__ == "__main__":
    analyze_pcap("logs/logs/files_192.168.0.213.pcap")