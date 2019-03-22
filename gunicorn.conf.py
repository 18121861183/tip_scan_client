#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by iFantastic on 19-2-21
import multiprocessing

bind = "127.0.0.1:8000"
workers = 2
errorlog = '/home/xxx/xxx/gunicorn.error.log'
accesslog = '/home/xxx/xxx/gunicorn.access.log'
proc_name = 'gunicorn_project'
