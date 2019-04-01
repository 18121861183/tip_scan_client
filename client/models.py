# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
import django.utils.timezone as timezone

# Create your models here.


class ScanTask(models.Model):
    id = models.CharField(max_length=40, verbose_name="ID", primary_key=True)
    command = models.TextField(verbose_name="指令")
    port = models.IntegerField(verbose_name="端口", default=0)
    protocol = models.CharField(max_length=100, verbose_name="扫描协议")
    ip_range = models.CharField(max_length=100, verbose_name="要探测的IP网段")
    ip_count = models.IntegerField(verbose_name="ip数量", default=0)
    zmap_result_path = models.CharField(max_length=150, verbose_name="zmap结果存储路径")
    zgrab_result_path = models.CharField(max_length=150, verbose_name="zgrab结果存储路径")
    ztag_result_path = models.CharField(max_length=150, verbose_name="ztag结果", null=True)
    issue_time = models.DateTimeField(default=timezone.activate(timezone="UTC"), verbose_name="接收指令时间")
    map_grab_time = models.DateTimeField(verbose_name="zmap和zgrab执行完成时间", null=True)
    finish_time = models.DateTimeField(verbose_name="全部执行完成时间", null=True)
    report_result_path = models.CharField(verbose_name="分析结果存储路径", max_length=200, null=True)
    report_file_md5 = models.CharField(verbose_name="分析报告的MD5值，用于完整性校验", null=True, max_length=40)
    execute_status = models.IntegerField(verbose_name="执行状态(0-未执行,1-正在执行,2-执行完成,-1-执行失败)", default=0)
    ztag_status = models.IntegerField(verbose_name="ztag执行状态(0-未执行,1-执行完成,-1-执行失败)", default=0)
    upload_status = models.IntegerField(verbose_name="上报中心状态(0-未上报,1-已上报,-1-上报失败)", default=0)
    priority = models.IntegerField(verbose_name="扫描优先级", default=0)
    online_count = models.IntegerField(verbose_name="online", default=0)
    zgrab_success_count = models.IntegerField(verbose_name="banner", default=0)
    ztag_handle_count = models.IntegerField(verbose_name="finger", default=0)

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

