# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
import django.utils.timezone as timezone

# Create your models here.


class ScanTask(models.Model):
    command = models.CharField(max_length=500, verbose_name="指令")
    port = models.IntegerField(verbose_name="端口", default=0)
    ip_count = models.IntegerField(verbose_name="ip数量", default=0)
    zmap_result_path = models.CharField(max_length=150, verbose_name="zmap结果存储路径")
    zgrab_result_path = models.CharField(max_length=150, verbose_name="zgrab结果存储路径")
    ztag_result_path = models.CharField(max_length=150, verbose_name="ztag结果", null=True)
    issue_time = models.DateTimeField(default=timezone.activate(timezone="UTC"), verbose_name="接收指令时间")
    map_grab_time = models.DateTimeField(verbose_name="zmap和zgrab执行完成时间", null=True)
    finish_time = models.DateTimeField(verbose_name="全部执行完成时间", null=True)
    execute_status = models.IntegerField(verbose_name="执行状态", default=0)
    ztag_status = models.IntegerField(verbose_name="ztag执行状态", default=0)
    upload_status = models.IntegerField(verbose_name="上报中心状态", default=0)
    priority = models.IntegerField(verbose_name="扫描优先级", default=0)

    def __str__(self):
        return self.command

    class Meta:
        verbose_name = "扫描指令"
        verbose_name_plural = verbose_name


class CloudUser(models.Model):
    username = models.CharField(max_length=64, verbose_name="节点用户名")
    password = models.CharField(max_length=64, verbose_name="密码")
    address = models.CharField(max_length=64, verbose_name="节点本机IP地址")
    port = models.IntegerField(verbose_name="rest接口端口", default=8000)

    def __str__(self):
        return self.username + self.address

    class Meta:
        verbose_name = "本机"
        verbose_name_plural = verbose_name
