#!/usr/bin/python
import sys
import optparse
import socket
from socket import *
from threading import Thread, Semaphore
import nmap

# screenLock = Semaphore(value=1)

"""port scaner using nmap"""


def nmapScan(targetHost, targetPort, nmapArgs):
    nScan = nmap.PortScanner()
    try:
        nScan.scan(targetHost, targetPort, nmapArgs)
        state = nScan[targetHost]['tcp'][int(targetPort)]['state']
        print "[*] " + targetHost + "tcp/" + targetPort + " " + state
    except Exception, e:
        print e

"""function using socket library"""
# def connScan(targetHost, targetPort):
#    try:
#        connSocket = socket(AF_INET, SOCK_STREAM)
#        connSocket.connect((targetHost, targetPort))
#        connSocket.send('TCP port garbage data\r\n')
#        screenLock.acquire()
#        results = connSocket.recv(200)
#        print '[+] %d/Tcp open'% targetPort
        # print str(results)
#        print 20*'-'
#    except Exception, e:
#        screenLock.acquire()
#        print e
#        print '[-] Tcp port closed'
#        print 20*'-'
#    finally:
#        screenLock.release()
#        connSocket.close()

"""function resolving host adres and starting nmap threads"""


def portScan(targetHost, targetPort, nmapArgs):
    try:
        targetIp = gethostbyname(targetHost)
    except:
        print '[-] Unknown host'
        return
    try:
        targetName = gethostbyaddr(targetIp)
        print '[+] Scan results for: ' + targetHost[0]
    except:
        print '[+] Scan results for: ' + targetIp
    setdefaulttimeout(1)
    for port in targetPort:
        print '[+] Scanning port: ' + port
        t = Thread(target=nmapScan, args=(targetIp, port, nmapArgs))
        t.start()


def nmapArgParser(nmapOption):
    return {
        "SYN": "-sS",
        "NULL": "-sN",
        "FIN": "-sF",
        "XMAS": "-sX",
    }.get(nmapOption, "")


def main():
    parser = optparse.OptionParser("%prog" + " -H <targetPort> -p <targetPort> -n <nmapArgs>")
    parser.add_option('-H', dest='targetHost', type='string', help='specify host')
    parser.add_option('-p', dest='targetPort', type='string', help='specify ports separated by ,')
    parser.add_option('-n', dest='nmapOption', type='string', default='', help='nmap scan type: SYN, NULL, FIN, XMAS')

    (options, args) = parser.parse_args()
    nmapOption = options.nmapOption
    nmapArgs = nmapArgParser(nmapOption)
    targetHost = options.targetHost
    targetPort = str(options.targetPort).split(',')
    if ((targetHost == None) | (targetPort[0] == None)):
        print "[-] Specify ports and host"
        exit(0)
    portScan(targetHost, targetPort, nmapArgs)

if __name__ == "__main__":
    sys.exit(main())
