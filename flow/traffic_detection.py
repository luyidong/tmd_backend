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

# 检测顺序: 域名规则的完全匹配, 基于机器学习的Uri行为检测以及敏感信息检测, Domain仿冒检测

import os
import urllib
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression

from utils_db import DBClient


class ModelDet(object):
    def __init__(self, good_query_file, bad_query_file):
        good_query_list = self.get_query_list(good_query_file)
        bad_query_list = self.get_query_list(bad_query_file)

        good_y = [0] * len(good_query_list)
        bad_y = [1] * len(bad_query_list)

        queries = bad_query_list + good_query_list
        print len(queries)
        y = bad_y + good_y

        self.v = TfidfVectorizer(tokenizer=get_ngrams)
        x = self.v.fit_transform(queries)

        x1, x2, y1, y2 = train_test_split(x, y, test_size=20, random_state=42)

        self.lgs = LogisticRegression()
        self.lgs.fit(x1, y1)

        print('Model Accuracy:{}'.format(self.lgs.score(x2, y2)))

    def __getstate__(self):
        return self.__dict__

    def predict(self, querie):
        return self.lgs.predict(self.v.transform([urllib.unquote(querie)]))[0]

    def get_query_list(self, file_name):
        rlist = []
        with open(file_name, 'r') as fp:
            for line in fp:
                try:
                    rlist.append(urllib.unquote(line).decode('utf-8'))
                except Exception as error:
                    print error
        return list(set(rlist))


def get_ngrams(query):
    return [query[i: i + 3] for i in range(0, len(query) - 3)]


def dumps_model(class_obj, model_name):
    with open(model_name, 'wb') as fp:
        pickle.dump(class_obj, fp)


def loads_model(model_name):
    return pickle.load(open(model_name, 'rb'))


def logi_init(g, b, model_name):
    if not os.path.exists(model_name):
        d = ModelDet(g, b)
        dumps_model(d, model_name)
        # print get_pickling_errors(d)
    return loads_model(model_name)


def get_pickling_errors(obj, seen=None):
    if seen is None:
        seen = []
    try:
        state = obj.__getstate__()
    except AttributeError:
        return
    if state is None:
        return
    if isinstance(state, tuple):
        if not isinstance(state[0], dict):
            state = state[1]
        else:
            state = state[0].update(state[1])
    result = {}
    for i in state:
        try:
            pickle.dumps(state[i], protocol=2)
        except pickle.PicklingError:
            if not state[i] in seen:
                seen.append(state[i])
                result[i] = get_pickling_errors(state[i], seen)
    return result


class RuleDet(object):
    def __init__(self, db_login_info, data_dir='data', model_name='model.pickle'):
        # 初始化DB,静态规则库,以及机器学习模型
        self.db_login_info = db_login_info
        self.data_dir = data_dir
        self.model_name = model_name
        self.db_client = DBClient(db_login_info)

        self.static_rule = dict()
        self.loads_static_rule()
        self.uri_model = None
        self.loads_uri_model()

    def loads_static_rule(self):  # 载入所有静态配置
        sql = """SELECT rule_type,mal_level,mal_type,mal_info,mal_description FROM rule_static where is_effect=1;"""
        r = self.db_client.search(sql)
        for i in r.fetchall():
            try:
                self.static_rule[i[3]] = dict(zip(['rule_type', 'mal_level', 'mal_type', 'mal_info', 'mal_description'],
                                                  list(i)))
            except:
                pass
        print 'loads {} static rule'.format(len(self.static_rule))

    def loads_uri_model(self):
        model_path = os.path.join(self.data_dir, self.model_name)
        if os.path.exists(model_path):
            self.uri_model = loads_model(model_path)
        else:
            pass
        print 'loads uri behavior model success'

    def custom_detection(self, content):
        sql = """SELECT rule_type,mal_level,mal_type,mal_info,mal_description 
                 FROM rule_custom where is_effect=1 and mal_info='%s';""" % content
        r = self.db_client.search(sql)
        rtuple = r.fetchone()
        if isinstance(rtuple, tuple):
            return dict(zip(['rule_type', 'mal_level', 'mal_type', 'mal_info', 'mal_description'], list(rtuple)))
        return None

    def static_detection(self, content):  # 静态检测
        if content in self.static_rule:
            return self.static_rule[content]
        return None

    def model_detection(self, content):  # 模型检测
        if self.uri_model.predict(content) == 1:
            return {"rule_type": "Model", "mal_level": 3, "mal_type": "uri_behavior", "mal_info": content,
                    "mal_description": "机器学习模型检出恶意url行为"}
        return None

    def detection(self, proto_data):  # 检测函数
        # 检测流程, ip, domain, uri_behavior
        dlist = []
        src_ip = proto_data.src_ip
        dst_ip = proto_data.dst_ip
        dlist.append(self.static_detection(src_ip))
        dlist.append(self.static_detection(dst_ip))
        dlist.append(self.custom_detection(src_ip))
        dlist.append(self.custom_detection(dst_ip))

        if proto_data.service == 'http':
            domain = proto_data.domain
            dlist.append(self.static_detection(domain or ''))
            dlist.append(self.custom_detection(domain or ''))
            uri = proto_data.uri
            dlist.append(self.model_detection(uri or ''))
        if proto_data.service == 'dns':
            query = proto_data.query
            dlist.append(self.static_detection(query or ''))
            dlist.append(self.custom_detection(query or ''))

        return [d for d in dlist if isinstance(d, dict)]


if __name__ == '__main__':
    login_info = {
        "host": "192.168.48.121",
        "port": 3306,
        "user": "root",
        "password": "123456",
        "db": "TMD",
        "charset": "utf8"
    }
    r = RuleDet(login_info)
    print r.custom_detection('goog1e.com')
    print r.custom_detection('10.10.10.100')
    print r.static_detection('ba1du.com')
    print r.static_detection('10.10.10.1')
    print r.model_detection('/admin?alert(1)')
    # data_dir = os.path.join('./', 'data')
    # w = logi_init(os.path.join(data_dir, 'normalqueries.txt'),
    #               os.path.join(data_dir, 'malqueries.txt'),
    #               os.path.join(data_dir, 'model.pickle'))
    # test = ['www.foo.com/id=1<script>alert(1)</script>',
    #         'www.foo.com/name=admin\' or 1=1',
    #         'abc.com/admin.php',
    #         '"><svg onload=confirm(1)>',
    #         'test/q=<a href="javascript:confirm(1)>',
    #         'q=../etc/passwd']
    # for i in test:
    #     print w.predict(i)
