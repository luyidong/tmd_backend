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


import os
from utils_db import bulk_insert_data
from utils_common import load_json_file


def import_rule(rule_file):
    print rule_file
    traffic_settings = load_json_file('settings.json')
    mysql_login_info = traffic_settings['mysql']
    ip_list, domain_list = [], []
    with open(rule_file, 'r') as fp:
        for line in fp:
            if line:
                try:
                    ip, domain = line.split(' ')
                    ip_list.append(ip.strip())
                    domain_list.append(domain.strip())
                except Exception as error:
                    print error
    set_ip_list = list(set(ip_list))
    set_domain_list = list(set(domain_list))
    bulk_ip_list = [{"rule_type": "Ip", "mal_level": 3,
                     "mal_type": "Static", "mal_info": ip,
                     "mal_description": "恶意IP", "is_effect": 1} for ip in set_ip_list]
    bulk_insert_data(bulk_ip_list, 'rule_static', mysql_login_info)
    bulk_domain_list = [{"rule_type": "Domain", "mal_level": 3,
                         "mal_type": "Static", "mal_info": domain,
                         "mal_description": "恶意域名", "is_effect": 1} for domain in set_domain_list]
    bulk_insert_data(bulk_domain_list, 'rule_static', mysql_login_info)
    print 'ip: {}, domain: {}'.format(len(set_ip_list), len(set_domain_list))


if __name__ == '__main__':
    import_rule(os.path.join('data', 'maldomain.txt'))
