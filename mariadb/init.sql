--===========================================================================
--  Auhtor:wYZ
--  Create Date:2018-04-26
--  Description:数据库初始化脚本
--===========================================================================
--  2018-04-26: New Sql Script
--============================================================================

-- set @debug='true';

CREATE DATABASE IF NOT EXISTS TMD  -- 流量数据库
    DEFAULT CHARSET utf8
    COLLATE utf8_general_ci;

USE TMD;

CREATE TABLE IF NOT EXISTS traffic (  -- 流量表, 应该通过日期分区
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
	ts TIMESTAMP NOT NULL,        -- 时间戳 datetime类型
	len SMALLINT NOT NULL,        -- 数据长度
	ttl SMALLINT NOT NULL,        -- TTL
	src_ip VARCHAR(15) NOT NULL,  -- 来源IP
	dst_ip VARCHAR(15) NOT NULL,  -- 目的IP
	sport SMALLINT NOT NULL,      -- 源端口
	dport SMALLINT NOT NULL,      -- 目的端口
	proto VARCHAR(5) NOT NULL,    -- 协议类型
	service VARCHAR(5) NOT NULL,  -- 应用层类型
	method VARCHAR(5),            -- http 请求方式
	uri VARCHAR(1024),            -- http 请求 uri
	host VARCHAR(128),            -- http 请求 host
	domain VARCHAR(128),          -- http or dns 请求域名
	ua VARCHAR(64),               -- http 请求 user-agen
	device VARCHAR(32),             -- http 请求设备类型
	nid SMALLINT,                 -- dns 请求
	op SMALLINT,                  -- dns 请求操作类型
	query VARCHAR(128),           -- dns 请求的host
	qip VARCHAR(15)              -- dns 请求返回的ip
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE IF NOT EXISTS mal (  -- 恶意事件表, 同样通过日期分区
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,  -- 恶意事件
    tid INT NOT NULL,                            -- traffic id 用于关联事件
    ts TIMESTAMP NOT NULL,                           -- 时间戳 datetime类型
    rule_type VARCHAR(128) NOT NULL,                 -- 威胁类型
    mal_type VARCHAR(128) NOT NULL,                  -- 威胁类型
    mal_level INT NOT NULL,                       -- 威胁等级
    mal_info VARCHAR(128) NOT NULL,                  -- 恶意事件内容
    src_ip VARCHAR(15) NOT NULL,                     -- 来源IP
	dst_ip VARCHAR(15) NOT NULL,                     -- 目的IP
	sport SMALLINT NOT NULL,                         -- 源端口
	dport SMALLINT NOT NULL,                         -- 目的端口
    proto VARCHAR(5) NOT NULL,                       -- 协议类型
	service VARCHAR(5) NOT NULL                     -- 应用层类型
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE IF NOT EXISTS static_rule (  -- 静态规则, 基于规则库, 极少变动的
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,  -- 规则id
    rule_type VARCHAR(128) NOT NULL,                  -- 规则类型 IP Domain
    mal_level INT NOT NULL,                      -- 威胁等级
    mal_type VARCHAR(128) NOT NULL,                 -- 威胁类型
    mal_info VARCHAR(128) NOT NULL,                 -- 规则内容
    mal_description VARCHAR(128),                   -- 规则描述
    is_effect INT DEFAULT 1                     -- 是否生效
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE IF NOT EXISTS custom_rule (  -- 自定义规则, 基于规则库, 极少变动的
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,   -- 规则id
    rule_type VARCHAR(128) NOT NULL,                   -- 规则类型 IP Domain
    mal_level INT NOT NULL,                       -- 威胁等级
    mal_type VARCHAR(128) NOT NULL,                  -- 威胁类型
    mal_info VARCHAR(128) NOT NULL,                  -- 规则内容
    mal_description VARCHAR(128),                    -- 规则描述
    is_effect INT DEFAULT 1,                      -- 是否生效
    create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- 创建时间
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- 插入数据部分
BEGIN;
-- 测试流量数据
INSERT INTO traffic
    (ts, len, ttl, src_ip, dst_ip, sport, dport, proto, service,
    method, uri, host, domain, ua, device, nid, op, query, qip)
VALUES
    (UNIX_TIMESTAMP(), 117, 64, '192.168.0.1', '192.168.0.10', 63012, 53, 'udp', 'dns',
    Null, Null, Null, Null, Null, Null, 64638, 256, 'baidu.com', '10.10.10.1'),
    (UNIX_TIMESTAMP(), 117, 64, '192.168.0.2', '192.168.0.10', 63019, 53, 'udp', 'dns',
    Null, Null, Null, Null, Null, Null, 64638, 256, 'baidu.com', '10.10.10.2'),
    (UNIX_TIMESTAMP(), 117, 64, '192.168.0.1', '10.10.10.1', 63517, 80, 'tcp', 'http',
    'GET', '/q?c=xxxxx', 'baidu.com', 'baidu.com', 'IOS', 'IOS', Null, Null, Null, Null);
-- 恶意事件数据
INSERT INTO mal
    (tid, ts, rule_type, mal_type, mal_level, mal_info, src_ip, dst_ip, sport, dport, proto, service)
VALUES
    (1, UNIX_TIMESTAMP(), '恶意IP', '未知类型', 2, '10.10.10.1', '192.168.0.1', '10.10.10.1', 61234, 80, 'tcp', 'http'),
    (2, UNIX_TIMESTAMP(), '恶意域名', '未知类型', 3, 'ba1du.com', '192.168.0.1', '10.10.10.1', 61234, 80, 'tcp', 'http');
-- 静态规则
INSERT INTO static_rule
    (rule_type, mal_level, mal_type, mal_info, mal_description, is_effect)
VALUES
    ('恶意IP', 2, '远程控制', '10.10.10.1', '远程控制CC服务器', 1),
    ('恶意域名', 2, '仿冒网站', 'ba1du.com', '仿冒百度', 1);
-- 自定义规则
INSERT INTO custom_rule
    (rule_type, mal_level, mal_type, mal_info, mal_description, is_effect)
VALUES
    ('恶意IP', 2, '远程控制', '10.10.10.101', '远程控制CC服务器', 1),
    ('恶意域名', 2, '仿冒网站', 'g00gle.com', '仿冒谷歌', 1);
COMMIT;  -- 提交事务