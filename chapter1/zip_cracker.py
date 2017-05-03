#!/usr/bin/python

import zipfile
import os
import sys
import optparse
from threading import Thread

def extractFile(zFile, password):
    try:
        zFile.extractall(pwd=password)
        return password
    except Exception, e:
        return
        #print e
        #pass #olewa exception

def main():
    parser = optparse.OptionParser("usage%prog " +\
            "-f <zipfile>")
    parser.add_option('-f', dest='zname', type='string', help='specify zip file')
    (option, args) = parser.parse_args()
    if (option.zname == None):
        print parser.usage
    else:
        zname = option.zname
    zFile = zipfile.ZipFile(zname)
    dictFile = open('dictionary.txt', 'r')
    for word in dictFile.readlines():
        word = word.strip('\n')
        t = Thread(target=extractFile, args=(zFile, word))
        t.start()
        guess = extractFile(zFile, word)
        if(guess == word):
            print "Found"
            exit(0)

if __name__ == "__main__":
    sys.exit(main())
