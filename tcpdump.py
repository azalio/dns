#!/usr/bin/env python
# coding: utf-8
#----------------------------------------------------

import pcapy
import dpkt
import operator
import re

two_words = {}
three_words = {}
four_words = {}
request_count = 0
percent_alert = 5
packet = 3000
tcpdump_filter = 'udp and dst port 53'
dev = 'eth0'
top_domains = {}
top_domain_list = []

def handle_packet(header,data):
	global two_words
	global three_words
	global four_words
	global request_count
	try:
		eth = dpkt.ethernet.Ethernet (data)
		if eth.type == dpkt.ethernet.ETH_TYPE_IP:
			ip = eth.data
			ip_data = ip.data
			if isinstance (ip_data, dpkt.udp.UDP):
				udp = ip_data
				if udp.dport == 53:
					try:
						dns = dpkt.dns.DNS(udp.data)
					except dpkt.dpkt.UnpackError:
						return
					try:
						name = dns.qd[0].name.split('.')
						name.reverse()
					except IndexError:
						return
					try:
						second_level = name[1] + "." + name[0]
						request_count += 1
						if second_level in two_words:
							two_words[second_level] += 1
						else:
							two_words[second_level] = 1
					except IndexError:
						pass
					try:
						third_level =  name[2] + "." + name[1] + "." + name[0]
						request_count += 1
						if third_level in three_words:
							three_words[third_level] += 1
						else:
							three_words[third_level] = 1
					except IndexError:
						pass
					try:
						fourth_level = name[4] + "." + name[2] + "." + name[1] + "." + name[0]
						request_count += 1
						if fourth_level in four_words:
							four_words[fourth_level] += 1
						else:
							four_words[fourth_level] = 1
					except IndexError:
						pass
	except:
		pass

p = pcapy.open_live(dev, 65536, False, 1)
p.setfilter(tcpdump_filter)
p.loop(packet, handle_packet)

sorted_2 = sorted(two_words.items(), key=operator.itemgetter(1))
sorted_3 = sorted(three_words.items(), key=operator.itemgetter(1))
sorted_4 = sorted(four_words.items(), key=operator.itemgetter(1))

for domain in sorted_2:
	(domain,count) = sorted_2.pop()
	if count > request_count/100*percent_alert:
		percent_of_req = count*100/request_count
		top_domains[domain] = percent_of_req
#		print domain,percent_of_req
	else:
		break

for domain in sorted_3:
	(domain,count) = sorted_3.pop()
	if count > request_count/100*percent_alert:
		percent_of_req = count*100/request_count
		top_domains[domain] = percent_of_req
#		print domain,percent_of_req
	else:
		break

for domain in sorted_4:
	(domain,count) = sorted_4.pop()
	if count > request_count/100*percent_alert:
		percent_of_req = count*100/request_count
		top_domains[domain] = percent_of_req
#		print domain,percent_of_req
	else:
		break

top_domain_list = top_domains.keys()
top_domain_string = ' '.join(top_domain_list)
for domain in top_domain_list:
	found = re.findall(domain, top_domain_string)
	if len(found) > 1:
		top_domain_list.remove(domain)

for domain in top_domain_list:
	print domain, top_domains[domain]
