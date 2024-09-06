# !/usr/bin/env python
# -*- coding:utf-8 -*-
# project name: SSLCertAutoIssue
# author: "Lei Yong" 
# creation time: 2024-09-03 21:50
# Email: leiyong711@163.com

import os
import re
import traceback
from utils.log import lg
from utils.config import Config
config = Config(True)

from app.qcloud_v3 import Qcloud
from utils.wx_noti import send_wx_noti
from datetime import datetime, timedelta
from app.letsencrypt.api import LetsencryptAPI
from apscheduler.schedulers.blocking import BlockingScheduler



let_api = LetsencryptAPI()
qcloud = Qcloud()
scheduler = BlockingScheduler()


def http_validation(acme_challenge: str, txt: str):
    """Nginx 配置修改"""
    old_acme_challenge = ""
    old_txt = ""
    acme_challenge_pattern = config.get_jsonpath('$.nginx_config.acme_challenge_pattern', '/.well-known/acme-challenge/([a-zA-Z0-9_]+)')
    acme_challenge_txt_pattern = config.get_jsonpath('$.nginx_config.acme_challenge_txt_pattern', 'return 200 "(.*?)"')
    nginx_config_path = config.get_jsonpath('$.nginx_config.path', '')

    nginx_config = ""
    try:
        try:
            with open(nginx_config_path, 'r') as f:
                nginx_config = f.read()
        except Exception as e:
            lg.error(f"读取 Nginx 配置文件错误，原因:\n{traceback.format_exc()}")

        match = re.search(acme_challenge_pattern, nginx_config)
        if match:
            old_acme_challenge = match.group(1)

        mathch = re.search(acme_challenge_txt_pattern, nginx_config)
        if mathch:
            old_txt = mathch.group(1)

        if not old_acme_challenge or not old_txt:
            lg.error("Nginx 配置文件解析错误，请检查配置文件是否正确")
            return False

        nginx_config = nginx_config.replace(old_acme_challenge, acme_challenge, 1)
        nginx_config = nginx_config.replace(old_txt, txt, 1)

        with open('new_'+ nginx_config_path, 'w') as f:
            f.write(nginx_config)

        return True
    except Exception as e:
        lg.error(f"更改 Nginx 配置错误，原因:\n{traceback.format_exc()}")
        return False


def verify_the_certificate(**kwargs):
    """验证SSL证书"""
    lg.info(f"{kwargs.get('job_name')}")

    # 获取SSL证书列表
    order_list = let_api.order_list()
    let_order_lists = {i['domains'][0].replace("*.", ""): i for i in order_list}

    # 获取域名配置文件列表
    domain_lists = config.get_jsonpath("$.domain_list", {})
    for k, v in domain_lists.items():

        # 排除SSL证书平台与配置文件中的不一致域名
        cert_id = let_order_lists.get(v['domain'], {}).get('id', '')
        if not cert_id:
            continue

        # 获取SSL证书详情
        order_info = let_api.certificate_details(cert_id)

        # 过期时间
        expiration_time = datetime.strptime(order_info['time_end'], '%Y-%m-%d %H:%M:%S')
        time_difference = expiration_time - datetime.now()
        days_difference = time_difference.days
        lg.info(f"域名 {v['domain']} SSL证书距离过期剩余 {days_difference} 天")

        lg.debug(f"order_info: {order_info}")

        # SSL证书提前续申请天数
        apply_for_days_in_advance = v.get("apply_for_days_in_advance", 3)

        # SSL证书验证通过
        if order_info.get('status') == "完成" and days_difference > apply_for_days_in_advance and kwargs.get('job_name') == 'SSL证书验签中，重新获取 所有权 验证结果':
            send_wx_noti(f"域名 {v['domain']} SSL证书验证通过，开始准备下载部署")
            lg.info(f"域名 {v['domain']} SSL证书验证通过，开始准备下载部署")
            zip_file_path = let_api.certificate_download(cert_id=cert_id)    # 下载证书
            let_api.deploy_ssl(zip_file_path, v['domain'])  # 部署证书
            lg.info(f"域名 {v['domain']} SSL证书部署完成，请检查域名是否正常访问")
            send_wx_noti(f"域名 {v['domain']} SSL证书部署完成，请检查域名是否正常访问", types="success")

        # SSL证书即将过期
        if days_difference <= apply_for_days_in_advance:

            if order_info.get('status') == "验证中":
                lg.info(f"域名 {v['domain']} SSL证书正处于验证中状态，三分钟后重新检测验签结果")
                scheduler.add_job(verify_the_certificate, 'date', id='验证证书', kwargs={"job_name": "SSL证书验签中，重新获取 所有权 验证结果"}, replace_existing=True, run_date=datetime.now() + timedelta(minutes=3))
                return

            elif order_info.get('status') == "待验证":
                lg.info(f"域名 {v['domain']} SSL证书正处于 待验证 状态")

                for verify in order_info['verify_data']:

                    if len(verify['check']) == 1:  # 只有DNS验证

                        lg.info(f"域名 {v['domain']} 进行 DNS 所有权验证，即将开始修改 域名解析 地址")

                        # 修改DNS
                        dns_service_providers = v.get("dns_service_providers", '')  # 获取DNS服务商
                        if not dns_service_providers:
                            lg.error(f"域名 {v['domain']} 未配置 DNS服务商，请先配置 DNS服务商")
                            return

                        dns_updata_status = False   # DNS修改状态
                        # 腾讯云DNS解析
                        if dns_service_providers == "Qcloud":
                            dns_updata_status = qcloud.modify_the_specified_dns_record(v['domain'], '_acme-challenge', verify['check']['dns-01']['txt'])

                        # 修改DNS失败
                        if not dns_updata_status:
                            send_wx_noti(f"域名 {v['domain']} DNS 所有权验证，修改 {dns_service_providers} DNS 解析失败，请检查域名解析是否正确", types="error")
                            scheduler.add_job(verify_the_certificate, 'date', id='验证证书', kwargs={"job_name": "SSL证书验签中，重新获取 所有权 验证结果"}, replace_existing=True, run_date=datetime.now() + timedelta(minutes=3))
                            return

                        lg.info(f"域名 {v['domain']} 即将开始进行 DNS 所有权验证")
                        status = let_api.certificate_validation(cert_id, f"{verify['id']}:{verify['check']['dns-01']['type']}")
                        if status:
                            send_wx_noti(f"域名 {v['domain']} 开始进行 DNS 所有权验证")
                            scheduler.add_job(verify_the_certificate, 'date', id='验证证书', kwargs={"job_name": "SSL证书验签中，重新获取 所有权 验证结果"}, replace_existing=True, run_date=datetime.now() + timedelta(minutes=3))
                            return

                    elif len(verify['check']) == 2:  # 同时有DNS和HTTP验证

                        # 二次验证方式 DNS/HTTP
                        second_verification_method = config.get_jsonpath(f'$.domain_list.{k}.second_verification_method')
                        if second_verification_method == 'DNS':
                            lg.info(f"域名 {v['domain']} 进行二次 DNS 所有权验证，即将开始修改 域名解析 地址")

                            # 修改DNS
                            dns_service_providers = v.get("dns_service_providers", '')  # 获取DNS服务商
                            if not dns_service_providers:
                                lg.error(f"域名 {v['domain']} 未配置DNS服务商，请先配置DNS服务商")
                                return

                            dns_updata_status = False   # DNS修改状态
                            # 腾讯云DNS解析
                            if dns_service_providers == "Qcloud":
                                dns_updata_status = qcloud.modify_the_specified_dns_record(v['domain'], '_acme-challenge', verify['check']['dns-01']['txt'])

                            # 修改DNS失败
                            if not dns_updata_status:
                                send_wx_noti(f"域名 {v['domain']} 二次 DNS 所有权验证，修改 {dns_service_providers} DNS 解析失败，请检查域名解析是否正确", types="error")
                                scheduler.add_job(verify_the_certificate, 'date', id='验证证书', kwargs={"job_name": "SSL证书验签中，重新获取 所有权 验证结果"}, replace_existing=True, run_date=datetime.now() + timedelta(minutes=3))
                                return

                            lg.info(f"域名 {v['domain']} 即将开始进行二次 DNS 所有权验证")
                            status = let_api.certificate_validation(cert_id, f"{verify['id']}:{verify['check']['dns-01']['type']}")
                            if status:
                                send_wx_noti(f"域名 {v['domain']} 开始进行二次 DNS 所有权验证")
                                scheduler.add_job(verify_the_certificate, 'date', id='验证证书', kwargs={"job_name": "SSL证书验签中，重新获取 所有权 验证结果"}, replace_existing=True, run_date=datetime.now() + timedelta(minutes=3))
                                return

                        elif second_verification_method == 'HTTP':

                            lg.info(f"域名 {v['domain']} 进行 HTTP 所有权验证，即将停止 Nginx 服务")
                            os.system('net stop nginx')
                            lg.info(f"域名 {v['domain']} 进行 HTTP 所有权验证，正在修改 Nginx 配置")

                            # 修改 Nginx 配置
                            if not http_validation(verify['check']['http-01']['filename'], verify['check']['http-01']['content']):
                                send_wx_noti(f"域名 {v['domain']} HTTP 所有权验证，修改 Nginx 配置文件失败", types="error")
                                scheduler.add_job(verify_the_certificate, 'date', id='验证证书', kwargs={"job_name": "SSL证书验签中，重新获取 所有权 验证结果"}, replace_existing=True, run_date=datetime.now() + timedelta(minutes=3))
                                return

                            os.system('net start nginx')
                            lg.info(f"域名 {v['domain']} 进行 HTTP 所有权验证，开始启动 Nginx 服务")

                            # 开始进行验签名
                            status = let_api.certificate_validation(cert_id, f"{verify['id']}:{verify['check']['http-01']['type']}")
                            if status:
                                send_wx_noti(f"域名 {v['domain']} 开始进行 HTTP 所有权验证")
                                scheduler.add_job(verify_the_certificate, 'date', id='验证证书', kwargs={"job_name": "SSL证书验签中，重新获取 所有权 验证结果"}, replace_existing=True, run_date=datetime.now() + timedelta(minutes=3))
                                return
                        else:
                            lg.error(f"域名 {v['domain']} 二次所有权验证方式配置错误")
                            return

                send_wx_noti(f"域名 {v['domain']} 证书申请失败，请手动申请", types="error")
                lg.warning(f"域名 {v['domain']} 证书申请失败，请手动申请")

            # 重新申请证书
            status, text = let_api.certificate_reapplication(cert_id)
            if status:
                send_wx_noti(f"域名 {v['domain']} SSL证书即将过期，剩余天数为 {days_difference} 天，开始尝试自动申请新的证书", types="warning")
                lg.info(f"域名 {v['domain']} 证书即将过期，开始申请新的证书")
                scheduler.add_job(verify_the_certificate, 'date', id='验证证书', kwargs={"job_name": "SSL证书验签中，重新获取 所有权 验证结果"}, replace_existing=True, run_date=datetime.now() + timedelta(minutes=3))
                return
            else:
                send_wx_noti(f"域名 {v['domain']} 证书申请失败，请手动申请，错误信息为：{text}", types="error")
                lg.warning(f"域名 {v['domain']} 证书申请失败，请手动申请，错误信息为：{text}")


def main():
    scheduler.add_job(verify_the_certificate, 'date', id='验证证书', kwargs={"job_name": "SSL证书验证"}, replace_existing=True, run_date=datetime.now() + timedelta(seconds=3))
    scheduler.add_job(verify_the_certificate, 'cron', kwargs={"job_name": "每日定时验证证书是否过期"}, hour=12, minute=30)
    lg.info("开始执行任务")
    scheduler.start()


if __name__ == '__main__':
    main()
