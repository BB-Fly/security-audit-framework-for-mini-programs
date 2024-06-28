# coding=utf-8 #

from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from os import path
import os
import sys
import datetime
from enum import Enum

current_directory = os.path.dirname(os.path.abspath(__file__)).replace("\\main", "")
sys.path.append(current_directory)
from config.config import *


class LogLevel(Enum):
    DEF = 0
    INF = 1
    DEBUG = 2
    WAR = 3
    ERR = 4


def lv2str(lv):
    if lv == LogLevel.DEF:
        return 'DEF'
    elif lv == LogLevel.DEBUG:
        return  'DEBUG'
    elif lv == LogLevel.INF:
        return 'INF'
    elif lv == LogLevel.WAR:
        return 'WAR'
    elif lv == LogLevel.ERR:
        return 'ERR'
    else:
        return 'DEF'
    


class baseModel:


    def __init__(self, name:str) -> None:
        cur_time = datetime.datetime.now()
        self.appName = name
        # log file
        self.log_dir = LOG_DIR + name + '-' + cur_time.strftime("%Y-%m-%d-%H-%M-%S\\")
        self.log_path = self.log_dir + "reports.txt"
        self.log_com_path = self.log_path
        self.log_idx = 0
        # url path
        self.url_path = self.log_dir + "urls.txt"
        # tools file
        self.tools_path = path.dirname("..\\"+TOOL_PATH)
        # python
        self.python_cmd = PY_CMD
        # sys
        self.sys = SYS

        self.urls:dict = {}
        if(os.path.exists(LOG_DIR)):
            pass
        else:
            os.mkdir(LOG_DIR)

        if(os.path.exists(self.log_dir)):
            pass
        else:
            os.mkdir(self.log_dir)

        pass

    def checkRequest(self, flow:HTTPFlow):
        pass

    def checkResponse(self, flow:HTTPFlow):
        pass

    def request(self, flow:HTTPFlow):
        self.checkRequest(flow)

    def response(self, flow:HTTPFlow):
        self.checkResponse(flow)

    def check_urls(self):
        pass

    def handle_log(self, f_name:str, url:str)->bool:
        pass

    def _REPORT(self, err:str):
        with open(self.log_com_path, '+a', encoding='utf-8') as fp:
            fp.write(err)

    def _LOG(self, err:str):
        with open(self.log_path, '+a', encoding='utf-8') as fp:
            fp.write(err)

    def REPORT(self, _out:str, _level:LogLevel = LogLevel.INF):

        out =  '<' + lv2str(_level) + '>潜在危险：' + _out + '\n'
        ctx.log.info(out)
        self._REPORT(out)
        self._LOG(out)
