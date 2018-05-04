# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.http import HttpResponse

from utils.utils_common import dumps_result, cross_domain, paginator, time_str_to_datetime

from .models import Custom, Static

# Create your views here.


def list_custom_rule(request):
    page = request.GET.get('page', 1)
    limit = request.GET.get('limit', 20)
    begin_time = request.GET.get('begin_time', None)
    end_time = request.GET.get('end_time', None)
    rule_type = request.GET.get('rule_type', None)
    mal_type = request.GET.get('mal_type', None)
    mal_info = request.GET.get('mal_info', None)
    mal_level = request.GET.get('mal_level', None)

    args_dict = dict()
    if rule_type:
        args_dict['rule_type'] = rule_type
    if mal_type:
        args_dict['mal_type'] = mal_type
    if mal_info:
        args_dict['mal_info'] = mal_info
    if begin_time:
        args_dict['create_time__gte'] = time_str_to_datetime(begin_time)
    if end_time:
        args_dict['create_time__lte'] = time_str_to_datetime(end_time)
    if mal_level:
        args_dict['mal_level'] = int(mal_level)

    result = dict()
    try:
        result["status"], result["tmd"] = 0, paginator(Custom, args_dict, page, limit, order='-create_time',
                                                       filter_field=['_state'], time_field=['create_time'])
    except Exception as error:
        result["status"], result["tmd"] = 1, str(error)
    finally:
        response = HttpResponse(dumps_result(result), content_type="application/json")
        return cross_domain(response)


def add_custom_rule(request):
    pass


def delete_custom_rule(request):
    pass


def operate_custom_rule(request):
    pass


def list_static_rule(request):
    page = request.GET.get('page', 1)
    limit = request.GET.get('limit', 20)
    rule_type = request.GET.get('rule_type', None)
    mal_type = request.GET.get('mal_type', None)
    mal_info = request.GET.get('mal_info', None)
    mal_level = request.GET.get('mal_level', None)

    args_dict = dict()
    if rule_type:
        args_dict['rule_type'] = rule_type
    if mal_type:
        args_dict['mal_type'] = mal_type
    if mal_info:
        args_dict['mal_info'] = mal_info
    if mal_level:
        args_dict['mal_level'] = int(mal_level)

    result = dict()
    try:
        result["status"], result["tmd"] = 0, paginator(Static, args_dict, page, limit, filter_field=['_state'])
    except Exception as error:
        result["status"], result["tmd"] = 1, str(error)
    finally:
        response = HttpResponse(dumps_result(result), content_type="application/json")
        return cross_domain(response)
