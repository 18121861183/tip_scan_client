#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by iFantastic on 19-1-22
from rest_framework import serializers

from client import models


class ScanTaskSerializers(serializers.ModelSerializer):

    class Meta:
        model = models.ScanTask
        fields = (
            "id",
            "command",
            "port",
            "ip_count",
            "zmap_result_path",
            "zgrab_result_path",
            "ztag_result_path",
            "issue_time",
            "map_grab_time",
            "finish_time",
            "execute_status",
            "ztag_status",
            "upload_status",
            "priority",
        )


class CloudUserSerializers(serializers.ModelSerializer):
    class Meta:
        model = models.CloudUser
        fields = (
            "id",
            "username",
            "password",
            "address",
            "port",
        )

