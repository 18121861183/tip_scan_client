# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import ipaddress
import json
import os
from apscheduler.schedulers.background import BackgroundScheduler
from django.http import HttpResponse
from django_apscheduler.jobstores import DjangoJobStore, register_events, register_job
from django.db.models import Sum
import tarfile
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from client import permissions, rsa_util, date_util, models
from tip_scan_client import settings
import logging
import subprocess


ports_protocol = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    110: 'pop3',
    143: 'imap',
    502: 'modbus',
    1911: 'fox',
    3306: 'mysql',
    47808: 'bacnet',
    20000: 'dnp3'
}

http_protocol = {
    80: 'http',
    443: 'http',
    8080: 'http',
}

ztag_command = {
    21: '-P ftp -S banner',
    22: '-P ssh -S v2',
    23: '-P telnet -S banner',
    25: '-P smtp -S starttls',
    80: '-P http -S get',
    110: '-P pop3 -S starttls',
    143: '-P imap -S starttls',
    443: '-P smtp -S starttls',
    502: '-P modbus -S device_id',
    1911: '-P fox -S device_id',
    3306: '-P mysql -S banner',
    8080: '-P http -S get',
    47808: '-P bacnet -S device_id',
    20000: '-P dnp3 -S status',
}


@api_view(['POST'])
@permission_classes((permissions.ServerCenterChecked, ))
def reveive_scan_task(request):

    if request.method == 'POST':
        task_encrypt = request.data['task']
        task_info = json.loads(rsa_util.rsa_decrypt(task_encrypt))
        network_list = task_info['list']
        for net in network_list:
            ip_count = len(list(ipaddress.ip_network(net).hosts()))
            for port in ports_protocol.keys():
                save_path = settings.scan_save_path + date_util.get_now_day_str() + '/'
                if os.path.exists(save_path) is False:
                    os.makedirs(save_path)
                file_name = str(net).replace('/', '_') + '_' + str(port)
                command = ['zmap', str(net), '--bandwidth', '10M', '--probe-module=icmp_echoscan', '-p', str(port),
                           '--output-fields=*', '|', 'ztee', save_path + file_name + '.csv',
                           '|', 'zgrab', '--port', str(port), '--' + ports_protocol.get(port),
                           '--output-file='+save_path + file_name + '.json']

                models.ScanTask.objects.create(command=" ".join(command), port=port, ip_count=ip_count, ztag_result_path=save_path+file_name+'_ztag.json',
                                               zmap_result_path=save_path + file_name + '.csv', zgrab_result_path=save_path + file_name + '.json',
                                               priority=5, issue_time=date_util.get_date_format(date_util.get_now_timestamp())).save()

        for net in network_list:
            ip_count = len(list(ipaddress.ip_network(net).hosts()))
            for port in ports_protocol.keys():
                save_path = settings.scan_save_path + date_util.get_now_day_str() + '/'
                if os.path.exists(save_path) is False:
                    os.makedirs(save_path)
                file_name = str(net).replace('/', '_') + '_' + str(port)
                command = ['zmap', str(net), '--bandwidth', '10M', '--probe-module=icmp_echoscan', '-p', str(port),
                           '--output-fields=*', '|', 'ztee', save_path + file_name + '.csv',
                           '|', 'zgrab', '--port', str(port), '--tls', '--http="/"',
                           '--output-file='+save_path + file_name + '.json']

                models.ScanTask.objects.create(command=" ".join(command), port=port, ip_count=ip_count, ztag_result_path=save_path+file_name+'_ztag.json',
                                               zmap_result_path=save_path + file_name + '.csv', zgrab_result_path=save_path + file_name + '.json',
                                               priority=5, issue_time=date_util.get_date_format(date_util.get_now_timestamp())).save()

        return HttpResponse("success")


# 客户端任务执行状态
@api_view(['GET', 'POST'])
@permission_classes((permissions.ServerCenterChecked, ))
def client_task(request):
    unscan_count = models.ScanTask.objects.filter(execute_status=0).aggregate(Sum('ip_count'))
    upload_list = models.ScanTask.objects.filter(execute_status=2).filter(upload_status=0).all()
    upload_array = []
    for upload in upload_list:
        upload_array.append(upload.__dict__)
    runing_list = models.ScanTask.objects.filter(execute_status=1).all()
    info = dict()
    info['number'] = unscan_count
    info['download'] = upload_array
    if runing_list is not None and len(runing_list) > 0:
        info['runing'] = runing_list[0].__dict__
    return Response(data=str(info), status=200, content_type='application/json')


@api_view(['POST', 'GET'])
def download_result(request, pk):
    task_info = models.ScanTask.objects.filter(id=pk).first()
    zmap = task_info.zmap_result_path
    grab = task_info.zgrab_result_path
    tag = task_info.ztag_result_path
    tar_pack = '/tmp/scan_result/'+pk+'scan_result.tar.gz'
    if os.path.exists('/tmp/scan_result/') is False:
        os.makedirs('/tmp/scan_result/')
    with tarfile.open(tar_pack, 'w') as tar:
        tar.add(zmap, arcname='zmap.csv')
        tar.add(grab, arcname='banner.json')
        tar.add(tag, arcname='ztag.json')
        tar.close()

    res_file = open(tar_pack, 'rb')
    # response = HttpResponse(res_file)
    # response['Content-Type'] = 'application/octet-stream'
    # response['Content-Disposition'] = 'attachment;filename="'+pk+'scan_result.tar.gz'+'"'
    return Response(res_file, content_type='application/octet-stream',
                    template_name=pk+'scan_result.tar.gz', headers='attachment')


# 定时扫描
# try:
#     logging.basicConfig()
#     # 实例化调度器
#     scheduler = BackgroundScheduler()
#     # 调度器使用DjangoJobStore()
#     scheduler.add_jobstore(DjangoJobStore(), "default")
#
#     # @register_job(scheduler, "interval", seconds=10, replace_existing=False)
#     # def heartbeat_job():
#     #     unscan_count = models.ScanTask.objects.filter(execute_status=0).aggregate(Sum('ip_count'))
#     #     print(unscan_count)
#     #     upload_list = models.ScanTask.objects.filter(execute_status=2).filter(upload_status=0).all()
#     #     print(upload_list)
#
#     @register_job(scheduler, 'interval', seconds=1, replace_existing=False)
#     def exec_command_job():
#         task_info = models.ScanTask.objects.filter(execute_status=0).first()
#         command = task_info.command
#         _id = task_info.id
#         models.ScanTask.objects.filter(id=_id).update(execute_status=1)
#         try:
#             subprocess.call(command, shell=True)
#             models.ScanTask.objects.filter(id=_id).update(execute_status=2, map_grab_time=date_util.get_date_format(date_util.get_now_timestamp()))
#         except BaseException as e1:
#             print(e1)
#             models.ScanTask.objects.filter(id=_id).update(execute_status=-1)
#
#     @register_job(scheduler, 'interval', seconds=1, replace_existing=False)
#     def exec_ztag_job():
#         print("检测zgrab完成的结果,进行ztag提取")
#         all_list = models.ScanTask.objects.filter(execute_status=2).filter(ztag_status=0).all()
#         for taks in all_list:
#             try:
#                 tag_path = taks.ztag_result_path
#                 port = taks.port
#                 grab_path = taks.zgrab_result_path
#                 subprocess.call('nohup cat '+grab_path+' | ztag -p'+str(port)+' -i '+grab_path+' '+ztag_command.get(port)+' > '+tag_path + ' &', shell=True)
#                 models.ScanTask.objects.filter(id=taks.id).update(ztag_status=1, finish_time=date_util.get_date_format(date_util.get_now_timestamp()))
#             except BaseException as e2:
#                 print(e2)
#                 models.ScanTask.objects.filter(id=taks.id).update(ztag_status=-1)
#
#     register_events(scheduler)
#     # 调度器开始
#     scheduler.start()
# except Exception as e:
#     print(e)
#     scheduler.shutdown()

