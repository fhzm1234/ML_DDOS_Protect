from scapy.all import*
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from flask import *
from time import *
import scapy.all as scapy
import os, threading, datetime, re, socket
import pandas as pd
import numpy as np
import ipaddress
import csv
import socket
import numpy

i = 1
pkt = 0
TCP_c = 0
ICMP_c = 0
UDP_c = 0
etc_c = 0
pkt_sum = 0
pkt_max = 0
pkt_min = 0
pkt_mean = 0
pkt_std = 0
ip_s = 0
port_s = 0
ip_d = 0
port_d = 0
proto = 0
byts_s = 0
pkt_s = 0
i_fin = 0
i_syn = 0
i_rst = 0
i_psh = 0
i_ack = 0
risk = 0
pkt_list = []
ip_list = list()
pt_list = list()
app = Flask(__name__)

def training():
    df = pd.read_csv('csv/sample.csv')

    X = df[['Src Port', 'Dst Port', 'Protocol', 'Tot Pkts', 'TCP Pkts', 'ICMP Pkts', 'UDP Pkts', 'Pkt Len Sum', 'Pkt Len Max', 
        'Pkt Len Min', 'Pkt Len Mean', 'Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 
        'FIN count', 'SYN count', 'RST count', 'PSH count', 'ACK count']]

    Y = df['Label']

    x_train, x_test, y_train, y_test = train_test_split(X, Y, stratify=Y, test_size=0.2, random_state=42)

    forest = RandomForestClassifier(n_estimators=30, random_state=2, max_depth=5)
    traing = forest.fit(x_train, y_train)

    print("Training Set Accuracy: {:.3f}".format(forest.score(x_train, y_train)))
    print("Test Set Accuracy: {:.3f}".format(forest.score(x_test, y_test)))

    return traing

def traffic(packet):

    global ip_s, port_s, ip_d, port_d, proto, pkt, TCP_c, ICMP_c, UDP_c, etc_c, pkt_sum, pkt_max, pkt_min, pkt_mean, pkt_std, i_fin, i_syn, i_rst, i_psh, i_ack
    
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10

    if(packet.haslayer(scapy.ICMP)):
        IP_icmp = packet['IP']
        ip_len_icmp = IP_icmp.len
        pkt_list.append(ip_len_icmp)
        ICMP_c += 1

    try:
        IP = packet['IP']
    except:
        return

    try:
        ip_s = IP.src
        ip_d = IP.dst
        port_s = IP.sport
        port_d = IP.dport
        proto = IP.proto
        ip_len = IP.len
    except:
        return

    #TCP

    if proto == 6:
        TCP = packet['TCP']
        if TCP.flags & FIN:
            i_fin += 1
        elif TCP.flags & SYN:
            i_syn += 1
        elif TCP.flags & RST:
            i_rst += 1
        elif TCP.flags & PSH:
            i_psh += 1
        elif TCP.flags & ACK:
            i_ack += 1
        TCP_c += 1
    elif proto == 17:
        UDP = packet['UDP']
        UDP_c += 1
    else:
        etc_c += 1


    pkt_list.append(ip_len)


def start():
	sleep(10)
	global ip_s, port_s, ip_d, port_d, proto, pkt, TCP_c, ICMP_c, UDP_c, etc_c, pkt_sum, pkt_max, pkt_min, pkt_mean, pkt_std, i_fin, i_syn, i_rst, i_psh, i_ack, risk
	while True:
		cap = sniff(prn=traffic, timeout=i)

		pkt = TCP_c + ICMP_c + UDP_c + etc_c
		pkt_sum = sum(pkt_list)

		if len(pkt_list) == 0:
			pkt_max = 0
		else:
			pkt_max = max(pkt_list)

		if len(pkt_list) == 0:
			pkt_min = 0
		else:
			pkt_min = min(pkt_list)

		if pkt_sum == 0:
			pkt_mean = 0
		else:
			pkt_mean = round((pkt_sum / pkt), 1)

		if len(pkt_list) == 0:
			pkt_std = 0
		else:
			pkt_std = round(numpy.std(pkt_list), 1)

		if pkt == 0:
			byts_s = 0
			pkt_s = 0
		else:
			byts_s = round((pkt / i), 1)
			pkt_s = round((pkt / i), 1)


		local_time = datetime.datetime.now().strftime('%H:%M:%S')


		X = pd.DataFrame([[port_s, port_d, proto, pkt, TCP_c, ICMP_c, UDP_c, pkt_sum, pkt_max, pkt_min, pkt_mean, pkt_std, byts_s, pkt_s, i_fin, i_syn, i_rst, i_psh, i_ack]], columns=['Src Port', 'Dst Port', 'Protocol', 'Tot Pkts', 'TCP Pkts', 'ICMP Pkts', 'UDP Pkts', 'Pkt Len Sum', 'Pkt Len Max', 'Pkt Len Min', 'Pkt Len Mean', 'Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'FIN count', 'SYN count', 'RST count', 'PSH count', 'ACK count'])
		b = a.predict(X)

		if b == 'SYN':
			risk = 1
			wrpcap('pcap/SYN.pcap', cap, append=True)
			sleep(1)
		elif b == 'UDP':
			risk = 2
			wrpcap('pcap/UDP.pcap', cap, append=True)
			sleep(1)
		elif b == 'ICMP':
			risk = 3
			wrpcap('pcap/ICMP.pcap', cap, append=True)
			sleep(1)
		else:
			risk = 0

    	#clear
		pkt_sum = 0
		pkt_max = 0
		pkt_min = 0
		pkt_mean = 0
		pkt_std = 0
		port_s = 0
		port_d = 0
		proto = 0
		pkt = 0
		TCP_c = 0
		ICMP_c = 0
		UDP_c = 0
		etc_c = 0
		byts_s = 0
		pkt_s = 0
		i_fin = 0
		i_syn = 0
		i_rst = 0
		i_psh = 0
		i_ack = 0
		pkt_list.clear()

def ipread():
	with open('logip', 'r') as ips:
		for line in ips:
			line = line[9: ]
			line = line.rstrip('\n')
			ip_list.append(line)

def ptread():
	with open('logpt', 'r') as pts:
		for line in pts:
			line = line[9: ]
			line = line.rstrip('\n')
			pt_list.append(line)


def ip_list_made(ip1):
	logi = open('logip', 'a')
	if re.match("[A]+", ip1):
		ip2 = ip1[1:]
		ip_list.append(ip2)
		add = "iptables -A INPUT -s " + str(ip2) + " -j DROP"
		os.system(add)
		data_print = datetime.datetime.now().strftime('%H:%M:%S') + " " +str(ip2) +"\n"
		logi.write(data_print)
	if re.match("[D]+", ip1):
		ip2 = ip1[1:]
		ip_list.remove(ip2)
		delete = "iptables -D INPUT -s " + str(ip2) + " -j DROP"
		os.system(delete)

		with open('logip', 'r+') as ips:
			lines = ips.readlines()
			ips.seek(0)
			for line in lines:
				if ip2 not in line:
					ips.write(line)
			ips.truncate()

def port_list_made(pt1):
	logi = open('logpt', 'a')
	if re.match("[C]+", pt1):
		pt2 = pt1[1:]
		pt_list.append(pt2)
		add = "iptables -A INPUT -p tcp --dport " + str(pt2) + " -j DROP" + "\n" + "iptables -A INPUT -p udp --dport " + str(pt2) + " -j DROP"
		os.system(add)
		data_print = datetime.datetime.now().strftime('%H:%M:%S') + " " +str(pt2) +"\n"
		logi.write(data_print)
	if re.match("[B]+", pt1):
		pt2 = pt1[1:]
		pt_list.remove(pt2)
		delete = "iptables -D INPUT -p tcp --dport " + str(pt2) + " -j DROP" + "\n" + "iptables -D INPUT -p udp --dport " + str(pt2) + " -j DROP"
		os.system(delete)

		with open('logpt', 'r+') as pts:
			lines = pts.readlines()
			pts.seek(0)
			for line in lines:
				if pt2 not in line:
					pts.write(line)
			pts.truncate()


def ddos_log():
	while True:
		if risk == 1:
			ddos_log = datetime.datetime.now().strftime('%H:%M:%S') + " " + "SYN Flooding Attack!\n" + "IP :" + str(ip_s) + " -> " + str(ip_d) + "  Port : " + str(port_s) + " -> " + str(port_d)
		elif risk == 2:
			ddos_log = datetime.datetime.now().strftime('%H:%M:%S') + " " + "UDP Flooding Attack!\n" + "IP :" + str(ip_s) + " -> " + str(ip_d) + "  Port : " + str(port_s) + " -> " + str(port_d)
		elif risk == 3:
			ddos_log = datetime.datetime.now().strftime('%H:%M:%S') + " " + "ICMP-based attack has arrived.\n" + "Block ICMP [ echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all ]\n" + "IP :" + str(ip_s) + " -> " + str(ip_d) + "  Port : " + str(port_s) + " -> " + str(port_d)
		else:
			ddos_log = datetime.datetime.now().strftime('%H:%M:%S') + " " + "This is a normal packet\n" + "IP :" + str(ip_s) + " -> " + str(ip_d) + "  Port : " + str(port_s) + " -> " + str(port_d)

		yield ddos_log
		sleep(1)


a = training()


@app.route('/', methods=['GET', 'POST'])
def index():
	if request.method == "POST":
		ip_black = request.form.get('ip_black')
		port_black = request.form.get('port_black')
		#print(ip_black)
		#print(port_black)
		if not ip_black:
			port_list_made(port_black)
			b = '<br>'.join(pt_list)
			return b
		else:
			ip_list_made(ip_black)
			a = '<br>'.join(ip_list)
			return a
	return render_template("index.html")


@app.route('/log')
def stream():
	rows = ddos_log()
	return Response(stream_with_context(stream_template('log.html', rows=rows)))

ipread()
ptread()
t = threading.Thread(target=start)
t.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7400, debug=False)
