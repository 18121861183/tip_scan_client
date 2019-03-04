# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import hashlib
import io
import subprocess
import thread
import time

import ipaddress
import json
import os
from django.http import HttpResponse, JsonResponse, FileResponse
from django.db.models import Sum
import tarfile
from rest_framework.decorators import api_view, permission_classes
from django.forms.models import model_to_dict

from client import permissions, rsa_util, date_util, models, hash_util
from tip_scan_client import settings

ports_protocol = {
    21: 'ftp',
    22: 'xssh',
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
    143: '-P imap -S starttls',
    443: '-P http -S get',
    502: '-P modbus -S device_id',
    1911: '-P fox -S device_id',
    3306: '-P mysql -S banner',
    8080: '-P http -S get',
    47808: '-P bacnet -S device_id',
    20000: '-P dnp3 -S status',
}

# models.ScanTask.objects.filter(execute_status=1).update(execute_status=0)


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
    task_info = models.ScanTask.objects.filter(command=record_id, execute_status=2, ztag_status=1).first()
    tar_pack = task_info.report_result_path

    _file = open(tar_pack)
    response = FileResponse(_file)
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="{0}"'.format(record_id + 'scan_result.tar.gz')

    return response


@api_view(['GET'])
@permission_classes((permissions.ServerCenterChecked,))
def success_info(request):
    record_id = None
    if request.method == 'GET':
        record_id = request.GET.get("id")
    elif request.method == 'POST':
        record_id = request.data['id']
    models.ScanTask.objects.filter(command=record_id, execute_status=2, ztag_status=1).update(upload_status=1)
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


def exec_command_job(delay):
    while True:
        task_info = models.ScanTask.objects.filter(execute_status=0).first()
        if task_info is not None:
            command = task_info.command
            models.ScanTask.objects.filter(command=command).update(execute_status=1)
            try:
                subprocess.call(command, shell=True)
                models.ScanTask.objects.filter(command=command).update(execute_status=2, map_grab_time=date_util.get_date_format(date_util.get_now_timestamp()))
            except BaseException as e1:
                print(e1)
                models.ScanTask.objects.filter(command=command).update(execute_status=-1)
        time.sleep(delay)


def report_detail(_id, zmap_path, zgrab_path, ztag_path, protocol, port):
    report_path = settings.report_save_path + date_util.get_now_day_str() + '/'
    if os.path.exists(report_path) is False:
        os.makedirs(report_path)

    filename = str(_id) + 'scan_result.tar.gz'

    with tarfile.open(report_path + filename, 'w:gz') as tar:
        tar.add(zmap_path, arcname='zmap.csv')
        tar.add(zgrab_path, arcname='banner_' + str(protocol) + '_' + str(port) + '.json')
        tar.add(ztag_path, arcname='ztag_' + str(protocol) + '_' + str(port) + '.json')
        tar.close()

    file_md5 = file_hash(report_path + filename)
    return report_path + filename, file_md5


def exec_ztag_job(delay):
    while True:
        all_list = models.ScanTask.objects.filter(execute_status=2).filter(ztag_status=0).all()
        if len(all_list) > 0:
            for taks in all_list:
                try:
                    tag_path = taks.ztag_result_path
                    port = taks.port
                    grab_path = taks.zgrab_result_path
                    subprocess.call('cat ' + grab_path + ' | ztag -p' + str(port) + ' -i ' + grab_path + ' ' + ztag_command.get(port) + ' > ' + tag_path, shell=True)
                    time.sleep(0.1)
                    report_path, md5 = report_detail(_id=taks.command, zmap_path=taks.zmap_result_path, zgrab_path=taks.zgrab_result_path,
                                                     ztag_path=taks.ztag_result_path, protocol=taks.protocol, port=taks.port)
                    models.ScanTask.objects.filter(command=taks.command).update(ztag_status=1, report_result_path=report_path, report_file_md5=md5, finish_time=date_util.get_date_format(date_util.get_now_timestamp()))
                    os.remove(taks.zmap_result_path)
                    os.remove(taks.zgrab_result_path)
                    os.remove(taks.ztag_result_path)
                except BaseException as e2:
                    print(e2)
                    models.ScanTask.objects.filter(command=taks.command).update(ztag_status=-1)
        time.sleep(delay)


# thread.start_new_thread(exec_command_job, (2,))
# thread.start_new_thread(exec_ztag_job, (2,))

