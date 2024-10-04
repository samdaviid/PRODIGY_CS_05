import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP

def main():
    while True:
        packets = sniff(count=10)  # Set a specific count for testing; adjust as needed.
        packet_info = []

        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
            else:
                src_ip = "N/A"
                dst_ip = "N/A"
                protocol = "N/A"

            packet_length = len(packet)
            packet_info.append([src_ip, dst_ip, protocol, packet_length])

        current_time = datetime.now()
        date = current_time.strftime("%d/%m/%Y")
        time = current_time.strftime("%H:%M:%S")

        # Create a DataFrame to store the packet information
        columns = ['Date', 'Time', 'Source IP', 'Destination IP', 'Protocol', 'Packet Size']
        data = pd.DataFrame([[date, time] + info for info in packet_info], columns=columns)

        with open('network_data.csv', 'a', newline='') as f:
            data.to_csv(f, index=False, header=f.tell()==0)  # Add header only if the file is empty

if __name__ == '__main__':
    main()
