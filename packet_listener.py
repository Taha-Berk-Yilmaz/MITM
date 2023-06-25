import scapy.all as scapy
from scapy_http import http 

def sniff(interface):
	scapy.sniff(iface = '{}'.format(interface), store = False, prn = analyze_packet)

def analyze_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		if packet.haslayer(scapy.Raw):
			print(packet[scapy.Raw].load)

try:
	interface = input("Interface: ")
	print("[#] Sniffing interface...")
	sniff(interface)

except KeyboardInterrupt:
	print("[#] Stopped sniffing...")
