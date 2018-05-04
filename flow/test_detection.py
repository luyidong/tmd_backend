#!/usr/bin/env python
# -*- coding: utf-8 -*- 

"""  
 @desc:  
 @author: Wyz
 @email: w4n9ya@gmail.com  
 @site: https://github.com/w4n9H/WyzBolg/issues 
 """

__author__ = "Wyz"
__version__ = "0.1"


from traffic_analysis import ProtoData
from traffic_detection import RuleDet, ModelDet, get_ngrams


def test_proto_detection():
    login_info = {
        "host": "192.168.48.121",
        "port": 3306,
        "user": "root",
        "password": "123456",
        "db": "TMD",
        "charset": "utf8"
    }
    r = RuleDet(login_info)
    http_proto_data = ProtoData()
    http_proto_data.src_ip = '10.10.10.1'
    http_proto_data.dst_ip = '192.168.1.1'
    http_proto_data.service = 'http'
    http_proto_data.domain = 'ba1du.com'

    dns_proto_data = ProtoData
    dns_proto_data.src_ip = '10.10.10.1'
    dns_proto_data.dst_ip = '192.168.1.1'
    dns_proto_data.service = 'dns'
    dns_proto_data.query = 'goog1e.com'
    print r.detection(http_proto_data)
    print r.detection(dns_proto_data)


if __name__ == '__main__':
    test_proto_detection()
