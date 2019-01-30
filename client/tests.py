# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os

print os.path.exists('/opt/scan_result/20190123/')

if os.path.exists('/opt/scan_result/20190123/') is False:
    os.makedirs('/opt/scan_result/20190123/')
