# !/usr/bin/env python
# -*- coding:utf-8 -*-
# project name: SSLCertAutoIssue
# author: "Lei Yong" 
# creation time: 2024-09-03 16:47
# Email: leiyong711@163.com
from utils.config import Config
config = Config(True)

import os
import math
import zipfile
import requests
import traceback
from utils.log import lg
from utils.config import Config
from utils.constants import APP_PATH

# config = Config()


class LetsencryptAPI:

    def __init__(self):
        self.token = config.get_jsonpath("$.letsencrypt.token", "")
        self.api_host = config.get_jsonpath("$.letsencrypt.api_host", "")
        self.user_name = config.get_jsonpath("$.letsencrypt.user_name", "")

    def request(self, url, method='GET', resp='JSON', **kwargs):
        self.headers = {
            "Authorization": f"Bearer {self.token}:{self.user_name}"
        }
        try:
            response = requests.request(method, self.api_host + url, headers=self.headers, timeout=5, **kwargs)
            
            # 记录响应状态和内容用于调试
            # lg.debug(f"API请求: {method} {self.api_host + url}")
            # lg.debug(f"响应状态码: {response.status_code}")
            # lg.debug(f"响应内容: {response.text[:500]}...")  # 只记录前500个字符
            
            if resp == 'File':
                return response
                
            # 尝试解析JSON
            try:
                return response.json()
            except requests.exceptions.JSONDecodeError as e:
                lg.error(f"JSON解析失败: {e}")
                lg.error(f"响应内容: {response.text}")
                return {}
                
        except requests.exceptions.RequestException as e:
            lg.error(f"网络请求异常: {e}")
            return {}
        except Exception as e:
            lg.error(f"Letsencrypt request error: {traceback.format_exc()}")
            return {}

    def account_info(self) -> dict:
        """账户信息"""
        r = self.request(url='/api/user/Account/info')
        # lg.warning(r)
        if not r.get('isError', True) and r.get('isOk', False):
            data = r.get('data', {})
            text = f"\n账户信息\n" \
                   f"用户类型：{data.get('user_type', '')}\n" \
                   f"邮箱：{data.get('email', '')}\n" \
                   f"手机号码：{data.get('phone', '')}\n" \
                   f"注册时间：{data.get('reg_time', '')}\n" \
                   f"SVIP到期时间：{data.get('svip_end', '')}\n" \
                   f"微信小程序绑定状态：{data.get('mnp_status', '')}\n" \
                   f"证书申请总数：{data.get('num_apply', '')}\n" \
                   f"证书申请成功总数：{data.get('num_apply_success', '')}\n" \
                   f"证书删除总数：{data.get('num_del_manual', '')}\n" \
                   f"积分数量：{data.get('num_coin', '')}\n" \
                   f"短信数量：{data.get('num_sms', '')}\n" \
                   f"独立通道数量：{data.get('num_channel', '')}\n"
            # lg.info(text)
        return data

    def order_list(self) -> list:
        """证书列表"""
        mpage = 1
        all = 1
        pnum = 10
        domain_list = []
        while mpage <= math.ceil(all / pnum):
            r = self.request(url='/api/user/Order/list', params={"page": mpage})
            # lg.debug(r)
            if not r.get('isError', True) and r.get('isOk', False):
                mpage += 1
                all = r.get('data', {}).get('all', 1)
                pnum = r.get('data', {}).get('pnum', 10)
                domain_list.extend(r.get('data', {}).get('list', []))
            else:
                break
        # for i in domain_list:
        #     text = f"\nID: {i.get('id')}\n" \
        #            f"域名清单: {i.get('domains')}\n" \
        #            f"证书备注: {i.get('mark')}\n" \
        #            f"证书颁发机构: {i.get('acme')}\n" \
        #            f"创建时间: {i.get('time_add')}\n" \
        #            f"到期时间: {i.get('time_end')}\n" \
        #            f"状态: {i.get('status')}\n" \
        #            f"自动状态: {i.get('auto_status')}\n" \
        #            f"是否使用独立通道: {i.get('quicker')}"
        # lg.debug(text)
        return domain_list

    def certificate_application(self, domains: str, algorithm: str = 'RSA', quick: str = 'no', ca: str = 'lets') -> str:
        """
        证书申请
        :param domains: [str, str]   域名,多个域名使用英文逗号分开。
        :param algorithm: str        证书加密算法，可传入：RSA,ECC。默认值：RSA
        :param quick: str            是否启用独立通道。yes代表启用(如果有)。默认值：no
        :param ca: str               CA渠道，可传入：lets,zerossl,buypass,google。默认值：lets
        :return: str 证书ID
        """
        params = {
            "domain": domains,
            "algorithm": algorithm,
            "quick": quick,
            "ca": ca
        }
        r = self.request(url=f'/api/user/Order/apply', params=params)
        # lg.debug(r)
        if not r.get('isError', True) and r.get('isOk', False):
            return r.get('data', {})
        return ""

    def certificate_reapplication(self, cert_id: str) -> str:
        """
        证书重新申请
        :param cert_id: 证书ID
        :return: 证书ID
        """
        r = self.request(url='/api/user/OrderDetail/renew', params={"id": cert_id})
        if not r.get('isError', True) and r.get('isOk', False):
            return True, r.get('data', {})
        return False, r.get('error', '')

    def certificate_details(self, cert_id: str) -> dict:
        """
        证书详情
        :param cert_id:
        :return: 验证信息 状态为需要验证时显示
        """
        r = self.request(url='/api/user/OrderDetail/info', params={"id": cert_id})
        # lg.debug(r)
        if not r.get('isError', True) and r.get('isOk', False):
            data = r.get('data', {})
            text = f"\n证书详情\n" \
                   f"证书ID: {data.get('id')}\n" \
                   f"域名清单：{data.get('domains', '')}\n" \
                   f"备注名：{data.get('mark', '')}\n" \
                   f"创建时间：{data.get('time_add', '')}\n" \
                   f"到期时间,或截至验证时间：{data.get('time_end', '')}\n" \
                   f"是否使用独立通道：{data.get('quicker', '')}\n" \
                   f"自动状态：{data.get('auto_status', '')}\n" \
                   f"证书状态：{data.get('status', '')}\n" \
                   f"是否可以下载证书：{data.get('can_download', '')}\n" \
                   f"是否可以清除秘钥：{data.get('can_clean', '')}\n" \
                   f"是否可以重新申请：{data.get('can_renew', '')}\n" \
                   f"是否可以删除：{data.get('can_delete', '')}\n" \
                   f"删除是否扣除积分：{data.get('can_delete_coin', '')}\n" \
                   f"是否可以设置自动模式：{data.get('can_auto', '')}\n" \
                   f"自动模式使用的ID：{data.get('auto_id', '')}\n" \
                   f"需要等待验证信息生成：{data.get('verify_wait', '')}\n"

            verify_data = data.get('verify_data', [])

            for i in verify_data:
                # lg.debug(i['check'])
                text += f"验证信息，状态为需要验证时显示\n" \
                        f"\t验证的域名：{i.get('domain', '')}\n" \
                        f"\t提交域名验证时标识，手动验证时显示：{i.get('id', '')}\n" \
                        f"\t验证的具体内容\n"
                for k, v in i.get('check', {}).items():
                    text += f"\t\t{k} 设置解析的完整域名：{v.get('dns', '')}\n" \
                            f"\t\t{k} 设置TXT解析的具体内容：{v.get('txt', '')}\n" \
                            f"\t\t{k} HTTP验证的完整网址：{v.get('url', '')}\n" \
                            f"\t\t{k} 访问验证地址输出的具体内容：{v.get('content', '')}\n"

                text += f"\t设置解析的完整域名：{i.get('dns', '')}\n" \
                        f"\t设置CNAME解析的具体内容：{i.get('txt', '')}\n"
            # lg.debug(text)
            return r.get('data', {})
        return {}

    def certificate_validation(self, cert_id: str, set: str = "123:dns-01;124:http-01"):
        """
        证书验证
        :param cert_id: 证书ID
        :param set: 需要验证的域名(id)和验证方式(具体值通过证书详情接口获取,位于verify_data)，一个id一般有两种验证方式（dns-01，http-01），需要选择其中一种(如果是泛域名，只有一种)。如果是自动验证无需填写。
        :return:
        """
        params = {
            "id": cert_id,
            "set": set
        }
        r = self.request(url='/api/user/OrderDetail/verify', params=params)
        if not r.get('isError', True) and r.get('isOk', False) and r.get('msg', '') == '提交成功,验证中':
            return True
        return False

    def certificate_download(self, cert_id: str, types: str = ""):
        """证书下载"""
        params = {
            "id": cert_id,
        }
        if types:
            params.update({"type": types})
        r = self.request(url='/api/user/OrderDetail/down', params=params, resp="File")
        # lg.debug(r.headers)
        # if r.headers.get('Content-Type', '') != "application/zip; charset=utf-8":
        #     return ""
        if r.status_code != 200:
            lg.error(f"证书下载失败，原因: {r.text}")
            return ""

        # 判断文件夹是否存在否，不存在则创建
        if not os.path.exists(f"{APP_PATH}/temp"):
            os.mkdir(f"{APP_PATH}/temp")

        with open(f"{APP_PATH}/temp/{cert_id}.zip", 'wb') as f:
            f.write(r.content)
            lg.info(f"证书下载成功！保存路径：{APP_PATH}/temp/{cert_id}.zip")
        return f"{APP_PATH}/temp/{cert_id}.zip"

    def deploy_ssl(self, zipfile_path, domain):
        """
        部署SSL
        :param zipfile_path: 证书压缩包
        :param domain: 域名
        :return:
        """
        domain = domain.replace(".", "@", -1)
        ssl_deployment_path = config.get_jsonpath(f'$.domain_list.{domain}.ssl_deployment_path')
        if not os.path.exists(f"{ssl_deployment_path}"):
            os.mkdir(f"{ssl_deployment_path}")
        zip_file = zipfile.ZipFile(zipfile_path, 'r')
        zip_file.extractall(ssl_deployment_path)
        zip_file.close()
        try:
            os.remove(zipfile_path)
        except:
            ...


if __name__ == '__main__':
    api = LetsencryptAPI()
    # data = api.certificate_details('1mj9ko')
    data = api.certificate_download('1mj9ko')
    lg.debug(data)
