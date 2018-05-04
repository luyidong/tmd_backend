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


import json
import math
import datetime

from django.core.paginator import Paginator
from django.core.paginator import EmptyPage
from django.core.paginator import PageNotAnInteger
from django.utils.timezone import localtime


def convert_bytes(bytes, t="bytes"):
    lst = ['bytes', 'kb', 'mb', 'gb', 'tb', 'pb']
    # return '%.2f' % (bytes / math.pow(1024, lst.index(t)))
    return int(bytes / math.pow(1024, lst.index(t)))


def dumps_result(r):
    try:
        return json.dumps(r)
    except Exception as error:
        raise Exception("{}".format(error))


def json_loads(j):
    try:
        return json.loads(j)
    except Exception as error:
        raise Exception("{}".format(error))


def cross_domain(response):
    # response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    # response["Access-Control-Max-Age"] = "1000"
    response["Access-Control-Allow-Headers"] = "*"
    # response["Access-Control-Allow-Headers"] = "Origin, X-Requested-With, Content-Type, Accept, If-Modified-Since"
    response['Access-Control-Allow-Credentials'] = 'true'
    return response


def paginator(model_object, args_dict, page, limit, order='-id', filter_field=None, time_field=None):
    paginator = Paginator(model_object.objects.filter(**args_dict).order_by(order), limit)
    try:
        return process_loaded(paginator.page(page), filter_field=filter_field, time_field=time_field)
    except PageNotAnInteger:
        return process_loaded(paginator.page(1), filter_field=filter_field, time_field=time_field)
    except EmptyPage:
        return process_loaded(paginator.page(paginator.num_pages), filter_field=filter_field, time_field=time_field)


def process_loaded(loaded, filter_field=None, time_field=None):
    rlist = []
    try:
        for i in loaded:
            rdata = i.__dict__
            if isinstance(filter_field, list):
                for f in filter_field:
                    del rdata[f]
            if isinstance(time_field, list):
                for t in time_field:
                    rdata[t] = localtime(rdata[t]).strftime('%Y-%m-%d %H:%M:%S')
            rlist.append(rdata)
        return rlist
    except:
        return rlist


def time_str_to_datetime(ts):
    return datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')


def get_args_funx(req, args_list):
    pass
