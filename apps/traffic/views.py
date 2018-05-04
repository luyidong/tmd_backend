# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.http import HttpResponse

from utils.utils_common import dumps_result, cross_domain, paginator, time_str_to_datetime

from .models import Normal, Mal

# Create your views here.


def show_normal_traffic(request):
    page = request.GET.get('page', 1)
    limit = request.GET.get('limit', 15)
    uid = request.GET.get('uid', None)
    begintime = request.GET.get('begin', None)
    endtime = request.GET.get('end', None)
    src_ip = request.GET.get('src_ip', None)
    dst_ip = request.GET.get('dst_ip', None)
    sport = request.GET.get('sport', None)
    dport = request.GET.get('dport', None)
    proto = request.GET.get('proto', None)
    service = request.GET.get('service', None)
    method = request.GET.get('method', None)
    host = request.GET.get('host', None)
    uri = request.GET.get('uri', None)
    domain = request.GET.get('domain', None)
    query = request.GET.get('query', None)
    qip = request.GET.get('qip', None)

    args_dict = dict()
    if uid:
        args_dict['uid'] = uid
    if begintime:
        args_dict['create_time__gte'] = time_str_to_datetime(begintime)
    if endtime:
        args_dict['create_time__lte'] = time_str_to_datetime(endtime)
    if src_ip:
        args_dict['src_ip'] = src_ip
    if dst_ip:
        args_dict['dst_ip'] = dst_ip
    if sport:
        args_dict['sport'] = int(sport)
    if dport:
        args_dict['dport'] = int(dport)
    if proto:
        args_dict['proto'] = proto
    if service:
        args_dict['service'] = service
    if method:
        args_dict['method'] = method.upper()
    if host:
        args_dict['host'] = host
    if uri:
        args_dict['uri'] = uri
    if domain:
        args_dict['domain'] = domain
    if query:
        args_dict['query'] = query
    if qip:
        args_dict['qip'] = qip

    result = dict()
    try:
        result["status"], result["tmd"] = 0, paginator(Normal, args_dict, page, limit, order='-ts',
                                                       filter_field=['_state'], time_field=['ts'])
    except Exception as error:
        result["status"], result["tmd"] = 1, str(error)
    finally:
        response = HttpResponse(dumps_result(result), content_type="application/json")
        return cross_domain(response)


def show_mal_traffic(request):
    page = request.GET.get('page', 1)
    limit = request.GET.get('limit', 15)
    uid = request.GET.get('uid', None)
    begintime = request.GET.get('begin', None)
    endtime = request.GET.get('end', None)
    src_ip = request.GET.get('src_ip', None)
    dst_ip = request.GET.get('dst_ip', None)
    sport = request.GET.get('sport', None)
    dport = request.GET.get('dport', None)
    proto = request.GET.get('proto', None)
    service = request.GET.get('service', None)
    rule_type = request.GET.get('rule_type', None)
    mal_type = request.GET.get('mal_type', None)
    mal_level = request.GET.get('mal_level', None)
    mal_info = request.GET.get('mal_info', None)

    args_dict = dict()
    if uid:
        args_dict['uid'] = uid
    if begintime:
        args_dict['create_time__gte'] = time_str_to_datetime(begintime)
    if endtime:
        args_dict['create_time__lte'] = time_str_to_datetime(endtime)
    if src_ip:
        args_dict['src_ip'] = src_ip
    if dst_ip:
        args_dict['dst_ip'] = dst_ip
    if sport:
        args_dict['sport'] = int(sport)
    if dport:
        args_dict['dport'] = int(dport)
    if proto:
        args_dict['proto'] = proto
    if service:
        args_dict['service'] = service
    if rule_type:
        args_dict['rule_type'] = rule_type
    if mal_type:
        args_dict['mal_type'] = mal_type
    if mal_level:
        args_dict['mal_level'] = int(mal_level)
    if mal_info:
        args_dict['mal_info'] = mal_info

    result = dict()
    try:
        result["status"], result["tmd"] = 0, paginator(Mal, args_dict, page, limit, order='-ts',
                                                       filter_field=['_state'], time_field=['ts'])
    except Exception as error:
        result["status"], result["tmd"] = 1, str(error)
    finally:
        response = HttpResponse(dumps_result(result), content_type="application/json")
        return cross_domain(response)

