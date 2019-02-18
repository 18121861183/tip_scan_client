# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os

# print os.path.exists('/opt/scan_result/20190123/')
#
# if os.path.exists('/opt/scan_result/20190123/') is False:
#     os.makedirs('/opt/scan_result/20190123/')
import random

rest = dict()
rest['1.1.1.1'] = 'xxxxxxxxxxxxxxxx'
print rest

all_keys = rest.keys()
print all_keys

key = random.choice(all_keys)
print key

