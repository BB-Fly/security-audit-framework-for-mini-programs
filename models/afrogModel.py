from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from models import baseModel
import os
import subprocess
import sys

current_directory = os.path.dirname(os.path.abspath(__file__)).replace("\\main", "")
sys.path.append(current_directory)
from config.config import *


class afrogModel(baseModel.baseModel):

    def __init__(self, name) -> None:
        super().__init__(name)
        self.log_path = self.log_dir + "afrog_log.txt"
        self.log_dir = self.log_dir + "afrog\\"

        if(os.path.exists(self.log_dir)):
            pass
        else:
            os.mkdir(self.log_dir)
    

    def checkRequest(self, flow: HTTPFlow):
        super().checkRequest(flow)

        url:str = flow.request.url

        if self.urls.get(url):
            return
        
        self.urls[url] = True


        if self.sys == ALL_SYS["Win"]:
            cmd_pre = self.tools_path + "\\afrog\\win\\afrog"
        elif self.sys == ALL_SYS["Mac"]:
            cmd_pre = self.tools_path + "\\afrog\\mac\\afrog"
        cmd = cmd_pre + " -t \"" + url + "\""

         # like: afrog -t https://example.com -a 1.json
        
        log_file = self.log_dir + str(self.log_idx) + ".txt"
        self.log_idx += 1

        ctx.log.info("afrog checking... " + url+"\n")

        with open(log_file, '+a') as fp:
            p = subprocess.Popen(cmd,stdin=subprocess.PIPE, stdout=fp, stderr=subprocess.PIPE)
            return_code = p.wait()

        res = self.handle_log(log_file, url)

        if res:
            ctx.log.info("afrog checked! " + url + "\n")
        else:
            self.REPORT("afrog checked! Potentially vulnerable objects found: " + url + "\n" + "!!!!!!!!Please check the log: " + log_file + '\n')


    def handle_log(self, f_name: str, url: str):
        lines = None
        out = " "
        res = True

        with open(f_name,'r+') as fp:
            lines = fp.readlines()

        for line in lines:
            if line.find("high") >= 0 or line.find("HIGH")>=0:
                res = False
                out = "afrog HIGH warning at the following URL: " + url
                self.REPORT(out)
            elif line.find("critical") >= 0 or line.find("CRITICAL")>=0:
                res = False
                out = "afrog CRITICAL warning at the following URL: " + url
                self.REPORT(out)

        return res