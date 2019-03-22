# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# !/usr/bin/env python
# -*- coding: utf-8 -*-
import psutil
import datetime
import time

# 当前时间
now_time = time.strftime(b"%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
print(now_time)
# 查看cpu的信息
print(u"物理CPU个数: %s" % psutil.cpu_count(logical=False))
print(u"逻辑CPU个数: %s" % psutil.cpu_count())
cpu = (str)(psutil.cpu_percent(1)) + '%'
print(u"cup使用率: %s" % cpu)
# 查看内存信息,剩余内存.free  总共.total
free = str(round(psutil.virtual_memory().free / (1024.0 * 1024.0 * 1024.0), 2))
total = str(round(psutil.virtual_memory().total / (1024.0 * 1024.0 * 1024.0), 2))
memory = int(psutil.virtual_memory().total - psutil.virtual_memory().free) / float(psutil.virtual_memory().total)
print(u"物理内存： %s G" % total)
print(u"剩余物理内存： %s G" % free)
print(u"物理内存使用率： %s %%" % int(memory * 100))
# 系统启动时间
print(u"系统启动时间: %s" % datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"))
# 系统用户
users_count = len(psutil.users())
users_list = ",".join([u.name for u in psutil.users()])
print(u"当前有%s个用户，分别是 %s" % (users_count, users_list))

print('-----------------------------磁盘信息---------------------------------------')
print ("系统磁盘使用情况：" + str(psutil.disk_usage('/')))


print('-----------------------------网卡信息-------------------------------------')
net_io_counters = psutil.net_io_counters(pernic=True)
for key in net_io_counters.keys():
    print(u"网卡名称：%s , %s " % (key, str(net_io_counters.get(key))))

# 当前的系统网络连接情况
print('-----------------------------系统网络访问信息-------------------------------------')
net_connections = psutil.net_connections()
for connect in net_connections:
    print(connect.fd, connect.family, connect.type, connect.laddr, connect.raddr, connect.status, connect.pid)


# 查看系统全部进程
# for pnum in psutil.pids():
#     p = psutil.Process(pnum)
#     print(u"进程名 %-20s  内存利用率 %-18s 进程状态 %-10s 创建时间 %-10s " % (p.name(), p.memory_percent(), p.status(), p.create_time()))






