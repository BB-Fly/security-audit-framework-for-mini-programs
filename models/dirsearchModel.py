# coding=utf-8 #

from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from models import baseModel
import os
import subprocess
import re


class dirsearchModel(baseModel.baseModel):

    def __init__(self, name) -> None:
        super().__init__(name)
        self.log_path =self.log_dir + "dirsearch_log.txt"
        self.log_dir = self.log_dir + "dirsearch\\"

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

        cmd_pre = self.python_cmd + self.tools_path + "\\dirsearch\\dirsearch.py "
        cmd = cmd_pre + " -u \"" + url + "\" -t 1 -i 200,201,201-300"

        log_file = self.log_dir + str(self.log_idx) + ".txt"
        self.log_idx += 1

         # like: python dirsearch.py -u "http://example.com" -i 200,201,201-300

        ctx.log.info("dirsearch checking... " + url+"\n")

        with open(log_file, '+a') as fp:
            p = subprocess.Popen(cmd,stdin=subprocess.PIPE, stdout=fp, stderr=subprocess.PIPE)
            return_code = p.wait()

        res = self.handle_log(log_file, url)
        if res:
            ctx.log.info("dirsearch checked! " + url + "\n")
        else:
            self.REPORT("dirsearch checked! 扫描出可访问的文件路径: " + url + "\n" + "!!!!!!!!Please check the log: " + log_file + '\n')


    def handle_log(self, f_name: str, url: str):
        lines = None
        out = " "
        res = True

        with open(f_name,'r+') as fp:
            lines = fp.readlines()

        pa = "\[.*:.*:.*\] [0-9][0-9][0-9] - .* - (.*)"

        for line in lines:

            mtch = re.match(pa, line)
            if mtch != None:
                res = False
                out = "dirsearch: 在该url发现隐藏路径: " + url + "\n路径名: " +  mtch[1] + '\n'
                self.REPORT(out)
        
        return res