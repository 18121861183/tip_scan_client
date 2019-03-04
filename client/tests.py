# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import hashlib
import io
import os

# print os.path.exists('/opt/scan_result/20190123/')
#
# if os.path.exists('/opt/scan_result/20190123/') is False:
#     os.makedirs('/opt/scan_result/20190123/')
import random


def file_hash(filepath):
    m = hashlib.md5()
    file = io.FileIO(filepath, 'r')
    bytes = file.read(1024)
    while bytes != b'':
      m.update(bytes)
      bytes = file.read(1024)
    file.close()
    md5value = m.hexdigest()
    return md5value


if __name__ == '__main__':
    print file_hash('/opt/page_url.json')

