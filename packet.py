#!/usr/bin/python

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