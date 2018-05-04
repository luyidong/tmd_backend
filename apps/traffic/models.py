# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.


class Normal(models.Model):
    ts = models.DateTimeField()
    uid = models.CharField(max_length=22)
    len = models.IntegerField()
    ttl = models.IntegerField()
    src_ip = models.CharField(max_length=15)
    dst_ip = models.CharField(max_length=15)
    sport = models.IntegerField()
    dport = models.IntegerField()
    proto = models.CharField(max_length=5)
    service = models.CharField(max_length=5)
    method = models.CharField(max_length=5, null=True)
    uri = models.CharField(max_length=1024, null=True)
    host = models.CharField(max_length=128, null=True)
    domain = models.CharField(max_length=128, null=True)
    ua = models.CharField(max_length=128, null=True)
    device = models.CharField(max_length=64, null=True)
    nid = models.IntegerField(null=True)
    op = models.IntegerField(null=True)
    query = models.CharField(max_length=128, null=True)
    qip = models.CharField(max_length=15, null=True)


class Mal(models.Model):
    uid = models.CharField(max_length=22)
    ts = models.DateTimeField()
    rule_type = models.CharField(max_length=128)
    mal_type = models.CharField(max_length=128)
    mal_level = models.IntegerField()
    mal_info = models.CharField(max_length=128)
    mal_description = models.CharField(max_length=128)
    src_ip = models.CharField(max_length=15)
    dst_ip = models.CharField(max_length=15)
    sport = models.IntegerField()
    dport = models.IntegerField()
    proto = models.CharField(max_length=5)
    service = models.CharField(max_length=5)
