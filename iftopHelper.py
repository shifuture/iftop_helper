#!/usr/bin/env python
# encoding: utf-8
'''
iftopHelper.py

@author:     Shifuture
@license:    MIT
'''

import re
import commands
from optparse import OptionParser

############################################
#
# PLEASE DO CHECK the instance nohup iftop -t > /var/log/iftop.log &
#
# CONFIG PARAMS
LOG_FILE="/var/log/iftop.log"
LOG_LINES=2000
BLOCK_PREFIX=['172.172.']
BLOCK_SKIP_IP=['172.172.0.1', '172.172.0.50']
BLOCK_IF_OVER=1024*1024*10 # over 10M
############################################

def readTail(fileName, lineNum):
    '''
    read tail lines of iftop log
    '''
    res=[]
    content=commands.getoutput('tail -'+str(lineNum)+' '+fileName)
    lines=re.findall("[\d\s]+\ +(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\ +=>\ +(.*B)\ +(.*B)\ +(.*B)\ +(.*B)\s+[\d ]+\ +(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\ +<=\ +(.*B)\ +(.*B)\ +(.*B)\ +(.*B)", content)
    return lines

def transPacketSize(ps):
    if ps.find('MB') >= 0:
        return int(1024*1024*float(ps.rstrip('MB')))
    elif ps.find('KB') >=0:
        return int(1024*float(ps.rstrip('KB')))
    else:
        return int(float(ps.rstrip('B')))

def getToBlockIp(ips):
    res={}
    for ip in ips:
        # over 10M in 40s
        if  ips[ip][2] > BLOCK_IF_OVER:
            res[ip]=ips[ip]
    return res

def isInBlockPrefix(ip):
    for prefix in BLOCK_PREFIX:
        if ip.find(prefix) == 0:
            return True
    return False

def block(ip):
    print("   IP -> %15s blocked"%ip)
    commands.getoutput("(/sbin/iptables -L -n -t filter|/bin/grep %s) || /sbin/iptables -I FORWARD -s %s -j DROP"%(ip,ip))

def initLimit():
    lines=readTail(LOG_FILE, LOG_LINES)
    connInfo={}
    for line in lines:
        if line[0] not in BLOCK_SKIP_IP and isInBlockPrefix(line[0]):
            if line[0] in connInfo:
                connInfo[line[0]] = [connInfo[line[0]][0]+transPacketSize(line[1])+transPacketSize(line[6]), 
                        connInfo[line[0]][1]+transPacketSize(line[2])+transPacketSize(line[7]), 
                        connInfo[line[0]][2]+transPacketSize(line[3])+transPacketSize(line[8])]
            elif line[0]:
                connInfo[line[0]] = [transPacketSize(line[1])+transPacketSize(line[6]), 
                        transPacketSize(line[2])+transPacketSize(line[7]), 
                        transPacketSize(line[3])+transPacketSize(line[8])]
        elif line[5] not in BLOCK_SKIP_IP and isInBlockPrefix(line[5]):
            if line[5] in connInfo:
                connInfo[line[5]] = [connInfo[line[5]][0]+transPacketSize(line[1])+transPacketSize(line[6]), 
                        connInfo[line[5]][1]+transPacketSize(line[2])+transPacketSize(line[7]), 
                        connInfo[line[5]][2]+transPacketSize(line[3])+transPacketSize(line[8])]
            elif line[5]:
                connInfo[line[5]] = [transPacketSize(line[1])+transPacketSize(line[6]), 
                        transPacketSize(line[2])+transPacketSize(line[7]), 
                        transPacketSize(line[3])+transPacketSize(line[8])]
    ips=getToBlockIp(connInfo)
    return ips

def main():
    parser = OptionParser("iftopHelper [-b <ip>] [-l list] [-a auto block] [-h help]")
    parser.add_option('-b','', dest="block_ip", help="block the ip provided")
    parser.add_option('-l','', dest="list", action="store_true", help="list all ip traffic info")
    parser.add_option('-a','--auto',dest="auto",action="store_true" , help="auto block the ip(s) which traffic is over limit")

    options,args=parser.parse_args()
    if options.block_ip and re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", options.block_ip) :
        block(options.block_ip)
    elif options.list or options.auto:
        ips=initLimit()
        if len(ips):
            print("OVER traffic ip:")
            for ip in ips:
                print("%15s:%10d %10d %10d"%(ip,ips[ip][0],ips[ip][1],ips[ip][2]))
            if options.auto:
                print("")
                for ip in ips:
                    block(ip)
        else:
            print("No IP OVER traffic.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
