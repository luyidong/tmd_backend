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


import uuid

from traffic_analysis import *
from traffic_capture import *
from traffic_detection import *

from utils_common import load_json_file, time_str_to_datetime
from utils_db import bulk_insert_data


def main():
    traffic_settings = load_json_file('settings.json')
    t = TrafficLite(device=traffic_settings['device'],
                    promisc=traffic_settings['promisc'],
                    snaplen=traffic_settings['snaplen'])
    print t.lib_version
    bpf_settings = traffic_settings['bpf']
    t.pcap_bpf(expr=bpf_settings['expr'], opt=bpf_settings['opt'], netmask=bpf_settings['netmask'])
    capture_type = traffic_settings['capture_type']
    mysql_login_info = traffic_settings['mysql']

    det = RuleDet(mysql_login_info)
    for i in t.start_next_ex():
        try:
            uid = uuid.uuid4().__str__().split('-', 2)[-1]
            normal_data = analysis_normal(i, uid)
            if normal_data.service in capture_type:
                normal_data_dict = normal_data.__dict__
                normal_data_dict['ts'] = time_str_to_datetime(normal_data_dict['ts'])
                # print normal_data_dict
                bulk_insert_data([normal_data_dict], 'traffic_normal', mysql_login_info)
                det_list = det.detection(normal_data)  # 检测结果列表
                if det_list and isinstance(det_list, list):
                    bulk_mal_list = [analysis_mal(normal_data, det_data, uid) for det_data in det_list]
                    # print bulk_mal_list
                    bulk_insert_data(bulk_mal_list, 'traffic_mal', mysql_login_info)
        except Exception as error:
            print '{}'.format(str(error))


if __name__ == '__main__':
    main()