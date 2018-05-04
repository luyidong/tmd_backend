# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.


class Static(models.Model):
    rule_type = models.CharField(max_length=128)
    mal_level = models.IntegerField()
    mal_type = models.CharField(max_length=128)
    mal_info = models.CharField(max_length=128)
    mal_description = models.CharField(max_length=128, null=True)
    is_effect = models.IntegerField(default=1)


class Custom(models.Model):
    rule_type = models.CharField(max_length=128)
    mal_level = models.IntegerField()
    mal_type = models.CharField(max_length=128)
    mal_info = models.CharField(max_length=128)
    mal_description = models.CharField(max_length=128, null=True)
    is_effect = models.IntegerField(default=1)
    create_time = models.DateTimeField(auto_now=True)
