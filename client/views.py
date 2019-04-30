# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import commands
import hashlib
import io
import multiprocessing
import subprocess
import thread
import time
from threading import Timer

import ipaddress
import json
import os

import requests
import urllib3
from django.http import HttpResponse, JsonResponse, FileResponse
from django.db.models import Sum
import tarfile
from rest_framework.decorators import api_view, permission_classes
from django.forms.models import model_to_dict

from client import permissions, rsa_util, date_util, models, hash_util
from tip_scan_client import settings

ports_protocol = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    110: 'pop3',
    143: 'imap',
    502: 'modbus',
    1911: 'fox',

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
    115: '-P ftp -S banner',
    139: '-P smb -S banner',
    143: '-P imap -S starttls',
    443: '-P http -S get',
    445: '-P smb -S banner',
    465: '-P smtp -S starttls',
    502: '-P modbus -S device_id',
    993: '-P imap -S starttls',
    994: '-P smtp -S starttls',
    995: '-P pop3 -S starttls',
    1433: '-P mssql -S banner',
    1521: '-P oracle -S banner',
    1911: '-P fox -S device_id',
    3306: '-P mysql -S banner',
    8080: '-P http -S get',
    5432: '-P postgres -S banner',
    27017: '-P mongodb -S banner',
    37017: '-P mongodb -S banner',
    47808: '-P bacnet -S device_id',
    20000: '-P dnp3 -S status',
}

try:
    models.ScanTask.objects.filter(execute_status=1).update(execute_status=0)
except BaseException as e:
    print(e, 'init error ')


urllib3.disable_warnings()


@api_view(['POST'])
@permission_classes((permissions.ServerCenterChecked,))
def receive_scan_task(request):
    if request.method == 'POST':
        task_encrypt = request.data['task']
        task_info = json.loads(rsa_util.rsa_decrypt(task_encrypt))
        network_list = task_info['list']
        print(network_list)
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
                           '--output-file=' + save_path + file_name + '.json']
                command_str = " ".join(command)
                _id = hash_util.get_sha1(command_str)
                print(_id)
                if models.ScanTask.objects.filter(id=_id).count() == 0:
                    models.ScanTask.objects.create(id=_id, command=command_str, port=port, protocol=ports_protocol.get(port),
                                                   ip_range=net, ip_count=ip_count, ztag_result_path=save_path + file_name + '_ztag.json',
                                                   zmap_result_path=save_path + file_name + '.csv', zgrab_result_path=save_path + file_name + '.json',
                                                   priority=5, issue_time=date_util.get_date_format(date_util.get_now_timestamp())).save()

        for net in network_list:
            ip_count = len(list(ipaddress.ip_network(net).hosts()))
            for port in http_protocol.keys():
                save_path = settings.scan_save_path + date_util.get_now_day_str() + '/'
                if os.path.exists(save_path) is False:
                    os.makedirs(save_path)
                file_name = str(net).replace('/', '_') + '_' + str(port)
                command = ['zmap', str(net), '--bandwidth', '10M', '--probe-module=icmp_echoscan', '-p', str(port),
                           '--output-fields=*', '|', 'ztee', save_path + file_name + '.csv',
                           '|', 'zgrab', '--port', str(port), '--tls', '--http="/"',
                           '--output-file=' + save_path + file_name + '.json']
                command_str = " ".join(command)
                _id = hash_util.get_sha1(command_str)
                print(_id)
                if models.ScanTask.objects.filter(id=_id).count() == 0:
                    models.ScanTask.objects.create(id=_id, command=command_str, port=port, protocol=http_protocol.get(port), ip_range=net,
                                                   ip_count=ip_count, ztag_result_path=save_path + file_name + '_ztag.json',
                                                   zmap_result_path=save_path + file_name + '.csv', zgrab_result_path=save_path + file_name + '.json',
                                                   priority=5, issue_time=date_util.get_date_format(date_util.get_now_timestamp())).save()

        return HttpResponse("success")


# 客户端任务执行状态
@api_view(['GET', 'POST'])
@permission_classes((permissions.ServerCenterChecked,))
def client_task(request):
    unscan_count = models.ScanTask.objects.filter(execute_status=0).aggregate(Sum('ip_count'))
    upload_list = models.ScanTask.objects.filter(execute_status=2).filter(ztag_status=1).filter(upload_status=0).all()
    upload_array = []
    number = 0
    for upload in upload_list:
        if number > 5:
            break
        upload_array.append(model_to_dict(upload))
        number += 1
    running_list = models.ScanTask.objects.filter(execute_status=1).all()
    if unscan_count['ip_count__sum'] is None:
        unscan_count = 0
    else:
        unscan_count = unscan_count['ip_count__sum']
    info = {'number': unscan_count, 'download': upload_array}
    running_array = []
    for i in running_list:
        json_dict = model_to_dict(i)
        running_array.append(json_dict)
    info['running'] = running_array
    return JsonResponse(info)


def download_result(request):
    record_id = request.GET.get("id")
    task_info = models.ScanTask.objects.filter(id=record_id, execute_status=2, ztag_status=1).first()
    tar_pack = task_info.report_result_path

    _file = open(tar_pack)
    response = FileResponse(_file)
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="{0}"'.format(record_id + 'scan_result.tar.gz')

    return response


@api_view(['GET', 'POST'])
@permission_classes((permissions.ServerCenterChecked,))
def success_info(request):
    record_id = None
    if request.method == 'GET':
        record_id = request.GET.get("id")
    elif request.method == 'POST':
        record_id = request.data['id']
    models.ScanTask.objects.filter(id=record_id, execute_status=2, ztag_status=1).update(upload_status=1)
    return HttpResponse('success')


def file_hash(file_path):
    m = hashlib.md5()
    _file = io.FileIO(file_path, 'r')
    _bytes = _file.read(1024)
    while _bytes != b'':
        m.update(_bytes)
        _bytes = _file.read(1024)
    _file.close()
    md5value = m.hexdigest()
    return md5value


def scan_start(task_info):
    command = task_info.command
    print("start running: ", command)

    try:
        # subprocess.call(command, shell=True)
        output = commands.getoutput(command)
        print(output)
        online_count = 0
        zgrab_success_count = 0
        try:
            result = output.split("\n")
            if len(result) > 0:
                execute_status = result[len(result) - 1]
                scan_info = json.loads(execute_status)
                status = scan_info.get('statuses')
                if len(status.keys()) > 0:
                    _info = status.get(status.keys()[0])
                    success = _info.get("successes")
                    failure = _info.get("failures")
                    zgrab_success_count = int(success)
                    online_count = int(success) + int(failure)
        except BaseException as e2:
            print(e2, "scan count get error:", command)
        models.ScanTask.objects.filter(id=task_info.id).update(execute_status=2, online_count=online_count,
                                                               zgrab_success_count=zgrab_success_count,
                                                               map_grab_time=date_util.get_date_format(
                                                                   date_util.get_now_timestamp()))
    except BaseException as e1:
        print(e1, command)
        models.ScanTask.objects.filter(id=task_info.id).update(execute_status=-1)


def exec_command_job(delay):
    while True:
        print("exec_command_job is running")
        task_info = models.ScanTask.objects.filter(execute_status=0).order_by('priority').first()
        if task_info is not None:
            models.ScanTask.objects.filter(id=task_info.id).update(execute_status=1)
            scan_start(task_info)
        time.sleep(delay)


def report_detail(_id, zmap_path, zgrab_path, ztag_path, protocol, port):
    report_path = settings.report_save_path + date_util.get_now_day_str() + '/'
    if os.path.exists(report_path) is False:
        os.makedirs(report_path)

    filename = str(_id) + 'scan_result.tar.gz'
    filepath = report_path + filename
    with tarfile.open(filepath, 'w:gz') as tar:
        tar.add(zmap_path, arcname='zmap.csv')
        tar.add(zgrab_path, arcname='banner_' + str(protocol) + '_' + str(port) + '.json')
        tar.add(ztag_path, arcname='ztag_' + str(protocol) + '_' + str(port) + '.json')

    file_md5 = file_hash(filepath)
    return filepath, file_md5


def exec_ztag_job(delay):
    while True:
        print("exec_ztag_job is running")
        all_list = models.ScanTask.objects.filter(execute_status=2).filter(ztag_status=0).all()
        if len(all_list) > 0:
            for taks in all_list:
                try:
                    tag_path = taks.ztag_result_path
                    port = taks.port
                    grab_path = taks.zgrab_result_path
                    shell_command = 'cat '+grab_path+' | ztag -p '+str(port)+' '+ztag_command.get(port)+' > '+tag_path
                    print shell_command
                    output = commands.getoutput(shell_command)
                    print(output)
                    records_handled = 0
                    try:
                        result = output.split("\n")
                        if len(result) > 0:
                            _info = result[len(result)-1]
                            rh = json.loads(_info).get('records_handled')
                            if rh is not None:
                                records_handled = int(rh)
                    except BaseException as e3:
                        print(e3, "error ZTag info", shell_command)
                    time.sleep(0.1)
                    report_path, md5 = report_detail(_id=taks.id, zmap_path=taks.zmap_result_path, zgrab_path=taks.zgrab_result_path,
                                                     ztag_path=taks.ztag_result_path, protocol=taks.protocol, port=taks.port)
                    models.ScanTask.objects.filter(id=taks.id).update(ztag_status=1, report_result_path=report_path, ztag_handle_count=records_handled,
                                                                      report_file_md5=md5, finish_time=date_util.get_date_format(date_util.get_now_timestamp()))
                    os.remove(taks.zmap_result_path)
                    os.remove(taks.zgrab_result_path)
                    os.remove(taks.ztag_result_path)
                except BaseException as e2:
                    print(e2.message)
                    models.ScanTask.objects.filter(id=taks.id).update(ztag_status=-1)
        time.sleep(delay)


def upload_center(delay):
    while True:
        try:
            base_path = settings.report_save_path
            if base_path.endswith('/') is False:
                base_path = base_path + '/'
            for sub_dir in os.listdir(base_path):
                sub_dir = base_path + sub_dir + '/'
                if os.path.isdir(sub_dir):
                    if len(os.listdir(sub_dir)) == 0:
                        continue
                    print(sub_dir)
                    for file_name in os.listdir(sub_dir):
                        _id = file_name[:40]
                        finish_task = models.ScanTask.objects.filter(id=_id).first()
                        data = {'port': finish_task.port,
                                'count': finish_task.ip_count,
                                'client_ip': '0.0.0.0',
                                'ip_range': finish_task.ip_range,
                                'time': finish_task.issue_time.time()}
                        files = {
                            "file": open(sub_dir + file_name, "rb")
                        }
                        response = requests.post('https://182.148.53.139:18081/dataExchange/upload4scan', data=data,
                                                 files=files, verify=False)
                        if response.json()['msg'] == 'success':
                            os.remove(sub_dir + file_name)
                            print(sub_dir+file_name, response.json())

        except BaseException as eu:
            print("upload_center", eu)
        time.sleep(delay)


# thread.start_new_thread(upload_center, (2,))

# thread.start_new_thread(exec_command_job, (2,))
thread.start_new_thread(exec_ztag_job, (2,))
# Timer(5, exec_command_job, (2, )).start()
# Timer(5, exec_ztag_job, (2, )).start()
#
#
# protocols = {
#     21: 'ftp',
#     22: 'ssh',
#     23: 'telnet',
#     25: 'smtp',
#     110: 'pop3',
#     115: 'ftp',
#     139: 'smb',
#     143: 'imap',
#     445: 'smb',
#     465: 'smtp',
#     993: 'imap',
#     994: 'smtp',
#     995: 'pop3',
#     1433: 'mssql',
#     1521: 'oracle',
#     3306: 'mysql',
#     5432: 'postgres',
#     27017: 'mongodb',
#     37017: 'mongodb'
# }
#
#
# def insert_data_more(network_list):
#     for net in network_list:
#         net = net.strip()
#         ip_count = 16777216
#         number = 1
#         for port in protocols.keys():
#             _id = hash_util.get_sha1(net)
#             zmap_result_path = '/opt/zmap/' + _id + '.csv'
#             zgrab_result_path = '/opt/zgrab2/' + _id + '.json'
#             ztag_result_path = '/opt/ztag/' + _id + '.json'
#
#             command = ['zmap', str(net), '--probe-module=icmp_echoscan -r 20000', '-p', str(port),
#                        '--output-fields=*', '|', 'ztee', zmap_result_path,
#                        '|', 'zgrab2', protocols.get(port), '--output-file='+zgrab_result_path]
#
#             command_str = " ".join(command)
#             _id = hash_util.get_sha1(command_str)
#             print(net, _id)
#             try:
#                 models.ScanTask.objects.create(
#                                 id=_id, command=command_str, port=port, protocol=protocols.get(port), ip_range=net,
#                                 ip_count=ip_count, ztag_result_path=ztag_result_path,
#                                 zmap_result_path=zmap_result_path, zgrab_result_path=zgrab_result_path,
#                                 priority=number, issue_time=date_util.get_date_format(date_util.get_now_timestamp())).save()
#                 number += 1
#             except Exception as et:
#                 print(et)
#                 continue
#
#
# _file = open('/home/zyc/ip_range.txt', 'r')
# net_array = []
# for line in _file.readlines():
#     if len(line.strip()) > 0:
#         net_array.append(line.strip())
#
# insert_data_more(net_array)

