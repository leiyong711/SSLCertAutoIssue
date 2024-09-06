# !/usr/bin/env python
# -*- coding:utf-8 -*-
# project name: SSLCertAutoIssue
# author: "Lei Yong" 
# creation time: 2024-09-06 15:43
# Email: leiyong711@163.com

import time
import traceback
import requests
from utils.config import Config
from utils.log import lg

config = Config()


def send_wx_noti(msg: str, types="success"):
    """
    发送微信通知
    :param msg: 通知内容
    :return:
    """
    wx_noti_host = config.get_jsonpath("$.we_chat_noti.wx_noti_host", "")
    wx_token = config.get_jsonpath("$.we_chat_noti.wx_token", "")
    if not wx_noti_host or not wx_token:
        lg.error("微信通知配置错误，请检查配置文件")
        return

    wx_room_noti = config.get_jsonpath("$.we_chat_noti.wx_room_noti", False)
    wx_room_id = config.get_jsonpath("$.we_chat_noti.wx_room_id", "")
    wx_id = config.get_jsonpath("$.we_chat_noti.wx_id", "")

    timer = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if types == "success":
        msg = f"⏰ {timer}\n✅ {msg}"
    elif types == "warning":
        msg = f"⏰ {timer}\n⚠️ {msg}"
    else:
        msg = f"⏰ {timer}\n❌ {msg}"

    data = {
        "text": msg,
        "wxcode": wx_id,
    }

    if wx_room_noti and wx_room_id:
        data['wxqun'] = wx_room_id

    try:
        r = requests.post(url=f"{wx_noti_host}/api/send_wx/{wx_token}", json=data).json()
        if r.get("code") != 200 or r.get("message") != "ok":
            lg.warning(f"微信通知失败，原因: {r.get('message')}")
    except Exception as e:
        lg.error(f"微信通知失败，原因: {traceback.format_exc()}")
