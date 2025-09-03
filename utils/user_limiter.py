# !/usr/bin/env python
# -*- coding:utf-8 -*-
# project name: SSLCertAutoIssue
# author: "Lei Yong" 
# creation time: 2024-09-03 16:47
# Email: leiyong711@163.com

import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict
from utils.log import lg
from utils.config import Config


class UserLimiter:
    """用户限制管理器"""
    
    def __init__(self):
        # 并发限制：1次/秒
        self.rate_limit_interval = 1.0  # 秒
        self.last_request_time = {}  # 用户最后请求时间
        
        # 每日次数限制
        self.daily_limits = {
            'normal': 100,    # 普通用户
            'vip': 500,       # VIP用户
            'svip': float('inf')  # SVIP不限制
        }
        
        # 用户每日请求计数
        self.daily_requests = defaultdict(lambda: {'count': 0, 'reset_date': None})
        
        # 线程锁
        self.lock = threading.Lock()
    
    def _get_user_type(self, user_name):
        """获取用户类型（这里需要根据实际情况实现）"""
        # 优先从缓存获取
        cached_type = getattr(self, '_user_type_cache', {}).get(user_name)
        if cached_type:
            return cached_type
        
        # 从配置文件获取
        try:
            config = Config(True)
            config_user_type = config.get_jsonpath("$.letsencrypt.user_type", "normal")
            return config_user_type
        except Exception as e:
            lg.warning(f"从配置文件获取用户类型失败: {e}")
            return 'normal'
    
    def set_user_type(self, user_name, user_type):
        """设置用户类型"""
        if not hasattr(self, '_user_type_cache'):
            self._user_type_cache = {}
        self._user_type_cache[user_name] = user_type
    
    def _reset_daily_count_if_needed(self, user_name):
        """如果日期变更，重置每日计数"""
        today = datetime.now().date()
        
        with self.lock:
            user_data = self.daily_requests[user_name]
            if user_data['reset_date'] != today:
                user_data['count'] = 0
                user_data['reset_date'] = today
    
    def check_rate_limit(self, user_name):
        """检查并发限制（1次/秒）"""
        current_time = time.time()
        
        with self.lock:
            last_time = self.last_request_time.get(user_name, 0)
            time_diff = current_time - last_time
            
            if time_diff < self.rate_limit_interval:
                # 计算需要等待的时间
                wait_time = self.rate_limit_interval - time_diff
                lg.info(f"用户 {user_name} 触发并发限制，等待 {wait_time:.1f} 秒...")
                time.sleep(wait_time)
                # 更新最后请求时间为当前时间
                self.last_request_time[user_name] = time.time()
                return True, f"并发限制等待完成，已等待 {wait_time:.1f} 秒"
            
            self.last_request_time[user_name] = current_time
            return True, "并发检查通过"
    
    def check_daily_limit(self, user_name):
        """检查每日次数限制"""
        self._reset_daily_count_if_needed(user_name)
        user_type = self._get_user_type(user_name)
        daily_limit = self.daily_limits.get(user_type, self.daily_limits['normal'])
        
        with self.lock:
            current_count = self.daily_requests[user_name]['count']
            
            if current_count >= daily_limit:
                return False, f"每日次数限制：{user_type.upper()}用户每日限制{daily_limit}次，今日已使用{current_count}次"
            
            return True, f"每日限制检查通过：{user_type.upper()}用户，今日已使用{current_count}次，剩余{daily_limit - current_count}次"
    
    def increment_request_count(self, user_name):
        """增加请求计数"""
        with self.lock:
            self.daily_requests[user_name]['count'] += 1
    
    def check_all_limits(self, user_name):
        """检查所有限制"""
        # 检查并发限制
        rate_ok, rate_msg = self.check_rate_limit(user_name)
        if not rate_ok:
            lg.warning(f"用户 {user_name} 并发限制检查失败: {rate_msg}")
            return False, rate_msg
        
        # 检查每日限制
        daily_ok, daily_msg = self.check_daily_limit(user_name)
        if not daily_ok:
            lg.warning(f"用户 {user_name} 每日限制检查失败: {daily_msg}")
            return False, daily_msg
        
        # 增加请求计数
        self.increment_request_count(user_name)
        
        lg.info(f"用户 {user_name} 限制检查通过: {daily_msg}")
        return True, daily_msg
    
    def get_user_stats(self, user_name):
        """获取用户统计信息"""
        self._reset_daily_count_if_needed(user_name)
        user_type = self._get_user_type(user_name)
        daily_limit = self.daily_limits.get(user_type, self.daily_limits['normal'])
        
        with self.lock:
            current_count = self.daily_requests[user_name]['count']
            remaining = daily_limit - current_count if daily_limit != float('inf') else float('inf')
            
            return {
                'user_type': user_type,
                'daily_limit': daily_limit,
                'current_count': current_count,
                'remaining': remaining,
                'reset_date': self.daily_requests[user_name]['reset_date']
            }


# 全局用户限制器实例
user_limiter = UserLimiter()
