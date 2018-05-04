#!/usr/bin/env python3  
# -*- coding: utf-8 -*- 

"""  
 @desc:  
 @author: Wyz
 @email: w4n9ya@gmail.com  
 @site: https://github.com/w4n9H/WyzBolg/issues 
 """

__author__ = "Wyz"
__version__ = "0.1"


import re
import json
import datetime
from tld import get_tld


def load_json_file(file_path):
    with open(file_path, 'r') as fp:
        return json.load(fp, encoding='utf-8')


def inet_to_str(inet):
    return '%d.%d.%d.%d' % tuple(map(ord, list(inet)))
    # try:
    #     return inet_ntop(AF_INET, inet)
    # except ValueError:
    #     return inet_ntop(AF_INET6, inet)


def ua_to_device(ua_str):
    # if ua_str:
    #     ua = parse(ua_str)
    #     os_family = '{} {}'.format(ua.os.family, ua.os.version_string).strip()
    #     return os_family, ua.device.family
    # return ua_str, ua_str
    r = re.findall(r'[^()]+', ua_str)
    if len(r) > 1:
        return r[1]
    return r[0]


def host_to_domain(host):
    try:
        if host.startswith('http'):
            return get_tld(host)
        else:
            return get_tld('http://{}'.format(host))
    except:
        return host


def time_str_to_datetime(ts):
    return datetime.datetime.strptime(ts, '%Y/%m/%d-%H:%M:%S')
