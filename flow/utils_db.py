#!/usr/bin/env python
# -*- coding: utf-8 -*- 

"""  
@desc: Mysql数据库操作,用于将流量写入DB
@author: Wyz
@email: w4n9ya@gmail.com
@site: https://github.com/w4n9H/WyzBolg/issues
"""

__author__ = "Wyz"
__version__ = "0.1"


import pymysql


class DBClient(object):
    def __init__(self, login_info, auto_close=True):
        self.conn = None
        self.cursor = None
        self.login_info = login_info
        self.auto_close = auto_close
        self.init()

    def init(self):
        try:
            self.conn = pymysql.connect(host=self.login_info.get('host', '127.0.0.1'),
                                        port=self.login_info.get('port', 3306),
                                        user=self.login_info.get('user', 'root'),
                                        password=self.login_info.get('password', ''),
                                        db=self.login_info.get('db', ''),
                                        charset=self.login_info.get('charset', 'utf8'))
            self.cursor = self.conn.cursor()
        except Exception as error:
            raise Exception('db init error, {}'.format(str(error)))

    def one_insert(self, table_name, data_dict):
        key_string = ''
        value_string = ''
        for dict_key, dict_value in data_dict.iteritems():
            key_string += '%s,' % dict_key
            value_string += "%%(%s)s" % dict_key + ','
        insert_sql = """INSERT INTO %s (%s) VALUES (%s);""" % (table_name, key_string[:-1], value_string[:-1])
        try:
            return self.cursor.execute(insert_sql, data_dict)
        except Exception as error:
            raise Exception('insert error, {}'.format(str(error)))

    def bulk_insert(self, table_name, data_list):
        for data in data_list:
            if isinstance(data, dict):
                try:
                    self.one_insert(table_name, data)
                except Exception as error:
                    print error
        self.commit()

    def search(self, sql):
        self.cursor.execute(sql)
        return self.cursor

    def commit(self):
        self.conn.commit()
        if self.auto_close:
            self.close()

    def close(self):
        self.cursor.close()
        self.conn.close()


def bulk_insert_data(data_list, table_name, login_info):
    db = DBClient(login_info)
    db.bulk_insert(table_name, data_list)


if __name__ == '__main__':
    import datetime
    login_info = {
        "host": "192.168.48.121",
        "port": 3306,
        "user": "root",
        "password": "123456",
        "db": "TMD",
        "charset": "utf8"
    }
    db_client = DBClient(login_info, auto_close=False)
    db_client.bulk_insert('rule_static', [{"rule_type": "Domain", "mal_level": 2,
                                           "mal_type": "fake", "mal_info": "ba1du.com",
                                           "mal_description": "仿冒百度", "is_effect": 1}])
    db_client.bulk_insert('rule_static', [{"rule_type": "Ip", "mal_level": 2,
                                           "mal_type": "c&c", "mal_info": "10.10.10.1",
                                           "mal_description": "CC服务器", "is_effect": 1}])
    db_client.bulk_insert('rule_custom', [{"rule_type": "Domain", "mal_level": 2,
                                           "mal_type": "fake", "mal_info": "goog1e.com",
                                           "mal_description": "仿冒谷歌", "is_effect": 1,
                                           "create_time": datetime.datetime.now()}])
    db_client.bulk_insert('rule_custom', [{"rule_type": "Ip", "mal_level": 2,
                                           "mal_type": "c&c", "mal_info": "10.10.10.100",
                                           "mal_description": "CC服务器", "is_effect": 1,
                                           "create_time": datetime.datetime.now()}])
    r = db_client.search('select * from rule_static;')
    for i in r.fetchall():
        print i
    db_client.close()



