#!/usr/bin/python

"""
Packet Sniffer
==============
  options:
    -s "10.0.0.1"        only parse packets with src/dst ip 10.0.0.1
    -h                   print this message
  
by schlerp, 2015
"""

import dpkt, pcap
import socket
import getopt
import sys


class Packet(object):
    """represents a packet, easy to use src, dst, data etc.."""
    src_ip = ''
    dst_ip = ''
    packet_type = ''
    data = r''
    data_hex = r''
    tcp_packet = r''
    packet_data = r''
    packet_ts = 0.0


class Capturer(object):
    """"""
    packet_list = []
    convo = []    

    def __init__(self, server, local=None):
        self.server = server
        self.local = local
        self.pc = pcap.pcap()
        print('listening on %s' % (self.pc.name))
        self.pc.loop(self._callback)
    
    
    def _callback(self, ts, pkt):
        """callback for pcap loop"""
        ether = dpkt.ethernet.Ethernet(pkt)
        if ether.type != dpkt.ethernet.ETH_TYPE_IP:
            return 0
        else:
            self.parse_packet(ts, ether)
        
        
    def parse_packet(self, ts, ether):
        temp = Packet()
        ip = ether.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        temp.src_ip = src
        temp.dst_ip = dst
        temp.packet_ts = ts
        temp.packet_type = ether.type
        temp.data_hex = "%r"%ip.data.data
        temp.tcp_packet = ip.data
        temp.packet_data = ip.data.data
        self.packet_list.append(temp)
        if self.server == None:
            self.convo.append(temp)
            self.output_packet(temp)            
        else:
            if temp.dst_ip == self.server or temp.src_ip == self.server:
                self.convo.append(temp)
                self.output_packet(temp)                      
        
                
    def output_packet(self, packet):
        print('===========================')
        print('time stamp: ' + str(packet.packet_ts))
        print("%s (src) -> %s (dst)" % (packet.src_ip, packet.dst_ip))
        print("packet type: " + str(packet.packet_type))
        print('===========================')
        print(r'%r'%packet.packet_data)
        print('===========================')
        print('\n')

def usage():
    str_usage = """
Packet Sniffer
==============
  options:
    -s "10.0.0.1"        only parse packets with src/dst ip 10.0.0.1
    -h                   print this message
  
by schlerp, 2015
    """
    print(str_usage)

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:h', ['server', 'help'])
    except getopt.GetoptError as e:
        print(str(e))
        usage()
        sys.exit(2)
    server = None
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif o in ("-s", "--server"):
            server = a
        else:
            assert False, "Unhandled option!"

    cap = Capturer(server)
    
    
if __name__ == '__main__':
    main()
    #cap = Capturer(const.training_tc)