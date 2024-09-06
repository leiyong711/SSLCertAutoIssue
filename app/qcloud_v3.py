# !/usr/bin/env python
# -*- coding:utf-8 -*-
# project name: SSLCertAutoIssue
# author: "Lei Yong" 
# creation time: 2024-09-05 15:40
# Email: leiyong711@163.com

import time
import hmac
import json
import hashlib
import requests
import traceback
from utils.log import lg
from datetime import datetime
from utils.config import Config

config = Config()


class Qcloud:

    service = "dnspod"
    host = "dnspod.tencentcloudapi.com"
    endpoint = "https://" + host
    region = "ap-guangzhou"
    version = "2017-03-12"
    algorithm = "TC3-HMAC-SHA256"
    signed_headers = "content-type;host;x-tc-action"

    def __init__(self, debug=False):
        """
        :param debug: 是否开启Debug日志
        """
        self.debug = debug
        self.secret_id = config.get_jsonpath('$.qcloud.secret_id', '')
        self.secret_key = config.get_jsonpath('$.qcloud.secret_key', '')

    def splice_the_specification_request_string(self, action, method, params):
        """
        拼接规范请求串
        :param action:  方法名
        :param method:  请求方法
        :param params:  参数
        :return:
        """
        http_request_method = method
        canonical_uri = '/'
        canonical_querystring = ""
        payload = json.dumps(params)

        ct = "application/json"
        canonical_headers = f"content-type:{ct}\nhost:{self.host}\nx-tc-action:{action.lower()}\n"

        hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        canonical_request = (http_request_method + "\n" +
                             canonical_uri + "\n" +
                             canonical_querystring + "\n" +
                             canonical_headers + "\n" +
                             self.signed_headers + "\n" +
                             hashed_request_payload)
        if self.debug:
            lg.debug(f"拼接规范请求串: \n{canonical_request}")
        return canonical_request

    def spell_the_reception_signature_string(self, action, method, params, timestamp, date):
        """
        拼接待签名字符串
        :param action:      方法名
        :param method:      请求方法
        :param params:      参数
        :param timestamp:   10位时间戳
        :param date:        时间日期
        :return:
        """
        credential_scope = date + "/" + self.service + "/" + "tc3_request"
        shign = self.splice_the_specification_request_string(action, method, params)
        hashed_canonical_request = hashlib.sha256(shign.encode("utf-8")).hexdigest()
        string_to_sign = (self.algorithm + "\n" +
                          str(timestamp) + "\n" +
                          credential_scope + "\n" +
                          hashed_canonical_request)
        if self.debug:
            lg.debug(f"拼接待签名字符串: \n{string_to_sign}")
        return string_to_sign

    def sign(self, key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def authorization(self, date, signature):
        credential_scope = date + "/" + self.service + "/" + "tc3_request"
        authorizations = (
                self.algorithm + " " +
                "Credential=" + self.secret_id + "/" + credential_scope + ", " +
                "SignedHeaders=" + self.signed_headers + ", " +
                "Signature=" + signature)
        return authorizations

    def requst(self, action, params, version, method="POST", **kwargs):
        timestamp = int(time.time())
        if self.debug:
            lg.debug(f"签名时间戳: {timestamp}")
        date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")

        secret_date = self.sign(("TC3" + self.secret_key).encode("utf-8"), date)
        secret_service = self.sign(secret_date, self.service)
        secret_signing = self.sign(secret_service, "tc3_request")
        sign = self.spell_the_reception_signature_string(action, method, params, timestamp, date)
        signature = hmac.new(secret_signing, sign.encode("utf-8"), hashlib.sha256).hexdigest()
        authorizations = self.authorization(date, signature)

        headers = {
            "Authorization": authorizations,
            "Content-Type": "application/json",
            "Host": self.host,
            "X-TC-Action": action,
            "X-TC-Timestamp": str(timestamp),
            "X-TC-Version": version,
            "X-TC-Region": self.region,
            "X-TC-Language": "zh-CN",
        }

        try:
            if self.debug:
                lg.debug(f"请求头: {headers}")
                lg.debug(f"请求参数: {params}")
            resp = requests.request(method, self.endpoint, json=params, headers=headers, timeout=7, **kwargs).json()
            if self.debug:
                lg.debug(f"返回数据: {resp}")
            return resp
        except Exception as e:
            lg.error(f"Qcloud请求异常: {traceback.format_exc()}")
            return {}

    def update_acme_challenge_analysis(self, domain,  value, params):
        """
        更新DNS解析
        :param domain:  域名
        :param value:   记录值
        :param params:  记录完整信息
        :return:
        """
        params = {
            "Domain": domain,
            "RecordType": params.get('Type'),
            "RecordLine": params.get('Line'),
            "Value": value,
            "RecordId": params.get('RecordId'),
            "TTL": params.get('TTL', 600),
            "SubDomain": params.get('Name', '@')
        }

        resp = self.requst('ModifyRecord', params, version="2021-03-23")
        if resp.get('Response', {}).get('Error', {}):
            lg.error(f"更新腾讯云DNS解析失败，异常原因：{resp.get('Response',{}).get('Error', {})}")
            return False
        return True

    def dns_parsing(self, domain, name=""):
        """
        获取DNS解析记录
        :param domain:  域名
        :param name:    返回指定记录名称，为空时返回所有记录
        :return:
        """
        params = {
            "Domain": domain,
        }
        resp = self.requst('DescribeRecordList', params, version="2021-03-23")

        if not name:
            return resp.get('Response', {}).get('RecordList', [])

        for i in resp.get('Response', {}).get('RecordList', []):
            if i.get('Name') == name:
                return [i]
        return []

    def modify_the_specified_dns_record(self, domain, name, value):
        """
        修改指定DNS记录
        :param domain:  域名
        :param name:    待修改的记录名称
        :param value:   记录值
        :return:
        """
        params = self.dns_parsing(domain, name)
        if not params:
            lg.error(f"未找到 {domain} 域名的 {name} 记录")
            return False

        status = self.update_acme_challenge_analysis(domain, value, params[0])
        if status:
            lg.info(f"将 {domain} 域名的{name}记录值从 {params[0].get('Value')} 修改为 {value} 成功")
            return True
        lg.warning(f"将 {domain} 域名的{name}记录值从 {params[0].get('Value')} 修改为 {value} 失败")
        return False
