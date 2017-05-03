#!/usr/bin/python

import socket
import sys
import os
import crypt

def testPass(cryptPass):
    print crypt.crypt("chuj", "HX")
    salt = cryptPass[0:2]
    print salt
    dictFile = open('dictionary.txt', 'r')
    for word in dictFile.readlines():
        cryptWord = crypt.crypt(word, salt)
        print cryptWord
        if (cryptWord == cryptPass):
            print 'Found: ' + word
            return
    print 'Not found'

def main():
    passwds = os.popen('sudo cat /etc/shadow | grep root').read()
    print passwds
    #passFile = open('passwords.txt')
    #print "dupa" + crypt.crypt('ziomeke1', '$6')
    if ':' in passwds:
        user = passwds.split(':')[0]
        cryptPass = passwds.split(':')[1].strip(' ')
        print "User: " + user
        testPass(cryptPass)
    print type(passwds)
if __name__ == "__main__":
    sys.exit(main())
