from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from models import baseModel
import os
import subprocess
import sys

current_directory = os.path.dirname(os.path.abspath(__file__)).replace("\\main", "")
sys.path.append(current_directory)
from config.config import *


class boltModel(baseModel.baseModel):

    def __init__(self, name) -> None:
        super().__init__(name)
        self.log_path = self.log_dir + "bolt_log.txt"
        self.log_dir = self.log_dir + "bolt\\"

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

        cmd_pre = self.python_cmd + self.tools_path + "\\Bolt\\bolt.py"
        cmd = cmd_pre + " -u \"" + url + "\" -l 2"

         # like: python bolt.py -u "https://example.com" -l 2
        
        log_file = self.log_dir + str(self.log_idx) + ".txt"
        self.log_idx += 1

        ctx.log.info("bolt checking... " + url+"\n")

        with open(log_file, '+a') as fp:
            p = subprocess.Popen(cmd,stdin=subprocess.PIPE, stdout=fp, stderr=subprocess.PIPE)
            return_code = p.wait()

        res = self.handle_log(log_file, url)

        if res:
            ctx.log.info("bolt checked! " + url + "\n")
        else:
            self.REPORT("bolt checked! Potentially vulnerable objects found: " + url + "\n" + "!!!!!!!!Please check the log: " + log_file + '\n')


    def handle_log(self, f_name: str, url: str):
        lines = None
        out = " "
        res = True

        with open(f_name,'r+') as fp:
            lines = fp.readlines()

        for line in lines:
            if line.find("Insecure form(s) found") >= 0:
                res = False
                out = "bolt: Insecure form(s) found at the following URL: " + url
                self.REPORT(out)

        return res