#!/usr/bin/env python
# -*- coding: utf-8 -*- 

"""  
 @desc: 流量解析模块
 @author: Wyz
 @email: w4n9ya@gmail.com  
 @site: https://github.com/w4n9H/WyzBolg/issues 
 """

__author__ = "Wyz"
__version__ = "0.1"


import time
import dpkt
from dpkt.ethernet import Ethernet

from utils_common import inet_to_str, host_to_domain, ua_to_device


class ProtoData(object):
    def __init__(self):
        # self.ti = None    # 整形时间戳
        self.ts = None    # 字符串时间戳
        self.uid = None
        self.len = None
        self.ttl = None
        self.src_ip = None
        self.dst_ip = None
        self.sport = None
        self.dport = None
        self.proto = None
        self.service = None
        # http
        self.method = None
        self.uri = None
        self.host = None
        self.domain = None
        self.ua = None
        self.device = None
        # dns
        self.nid = None
        self.op = None
        self.query = None
        self.qip = None


class MalData(object):
    def __init__(self):
        self.uid = None
        self.ts = None
        self.rule_type = None
        self.mal_type = None
        self.mal_level = None
        self.mal_info = None
        self.mal_description = None
        self.src_ip = None
        self.dst_ip = None
        self.sport = None
        self.dport = None
        self.proto = None
        self.service = None


def analy_ts(po, p_header, stamp='%Y/%m/%d-%H:%M:%S'):
    po.ts = time.strftime(stamp, time.localtime(int(p_header.ts.tv_sec)))


def analy_ip(po, ip_data):
    po.len = ip_data.len or 0
    po.ttl = ip_data.ttl or 0
    po.src_ip = inet_to_str(ip_data.src)
    po.dst_ip = inet_to_str(ip_data.dst)


def analy_http(po, tcp_data):
    po.sport = tcp_data.sport or 0
    po.dport = tcp_data.dport or 0
    po.proto = 'tcp'
    po.service = 'http'
    http_request = dpkt.http.Request(tcp_data.data)
    po.method = http_request.method or ''
    po.uri = http_request.uri or ''
    header = http_request.headers
    po.host = header.get('host', '')
    po.domain = host_to_domain(po.host)
    po.ua = header.get('user-agent', '')
    po.device = ua_to_device(po.ua)


def analy_dns(po, udp_data):
    po.sport = udp_data.sport or 0
    po.dport = udp_data.dport or 0
    po.proto = 'udp'
    po.service = 'dns'
    dns = dpkt.dns.DNS(udp_data.data)
    po.nid = dns.id
    po.op = dns.op
    qd_list = dns.qd
    if qd_list:
        if hasattr(qd_list[0], 'name'):
            po.query = qd_list[0].name  # ','.join([i.name for i in qd_list if hasattr(i, 'name')])
            po.domain = host_to_domain(po.query)
    an_list = dns.an
    if an_list:
        if hasattr(an_list[0], 'ip'):
            po.qip = inet_to_str(an_list[0].ip)  # ','.join([inet_to_str(i.ip) for i in an_list if hasattr(i, 'ip')])


# def analy_email(p_header, p_data):
#     pass


# noinspection PyTypeChecker
def analysis_normal(packet, uid):
    try:
        proto_data = ProtoData()
        proto_data.uid = uid
        if isinstance(packet, tuple):
            p_header, p_data = packet
            analy_ts(proto_data, p_header)  # 解析时间
            p = Ethernet(p_data)
            if isinstance(p.data, dpkt.ip.IP):
                ip_data = p.data
                analy_ip(proto_data, ip_data)
                if isinstance(ip_data.data, dpkt.tcp.TCP):
                    tcp_data = ip_data.data
                    if tcp_data.data[:3] == "GET" or tcp_data.data[:4] == "POST":
                        analy_http(proto_data, tcp_data)
                if isinstance(ip_data.data, dpkt.udp.UDP):
                    udp_data = ip_data.data
                    if udp_data.dport == 53 or udp_data.sport == 53:
                        analy_dns(proto_data, udp_data)
        return proto_data
    except Exception as error:
        raise Exception("{}".format(error))


def analysis_mal(normal_data, mal_dict, uid):
    try:
        mal_data = MalData()
        mal_data.uid = uid
        mal_data.ts = normal_data.ts
        mal_data.rule_type = mal_dict.get('rule_type', '')
        mal_data.mal_type = mal_dict.get('mal_type', '')
        mal_data.mal_level = mal_dict.get('mal_level', '')
        mal_data.mal_info = mal_dict.get('mal_info', '')
        mal_data.mal_description = mal_dict.get('mal_description', '')
        mal_data.src_ip = normal_data.src_ip
        mal_data.dst_ip = normal_data.dst_ip
        mal_data.sport = normal_data.sport
        mal_data.dport = normal_data.dport
        mal_data.proto = normal_data.proto
        mal_data.service = normal_data.service
        return mal_data.__dict__
    except Exception as error:
        raise Exception("{}".format(error))
