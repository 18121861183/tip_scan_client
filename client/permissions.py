#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by iFantastic on 19-1-22
import json

from rest_framework import permissions

from client import rsa_util, models


class ServerCenterChecked(permissions.BasePermission):

    def has_permission(self, request, view):
        authenticate_code = request.data['authenticate_code']
        if authenticate_code is None or len(authenticate_code) == 0:
            return False
        base_info = rsa_util.rsa_decrypt(str(authenticate_code))
        message_obj = json.loads(base_info)
        client_info = models.CloudUser.objects.get(username=message_obj['username'])
        if client_info is None:
            return False
        else:
            if message_obj['username'] == client_info.username \
                    and message_obj['password'] == client_info.password \
                    and message_obj['address'] == client_info.address \
                    and message_obj['port'] == client_info.port:
                return True
            else:
                return False
