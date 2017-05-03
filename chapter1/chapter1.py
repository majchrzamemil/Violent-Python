#!/usr/bin/python2.7
import socket
import sys
import os

def connectToSocket(ip, s, port):
    if len(sys.argv) == 2:
        print sys.argv[1]
    socket.setdefaulttimeout(1)
    soc = socket.socket()
    try:
        soc.connect((ip, int(s)))
        baner = soc.recv(port)
        return baner
    except Exception, e:
        return str(e)

def openFile():
    obj = open("examplefile", 'r')
    for line in obj.readlines():
        print line

def main():
    openFile()
    #os.mkdir("abv")
    ip = "192.168.95.148"
    soc = 21
    port = 104
    print connectToSocket(ip,soc,port)
    for x in range(1,10):
        print x

if __name__ == "__main__":
    sys.exit(main())
