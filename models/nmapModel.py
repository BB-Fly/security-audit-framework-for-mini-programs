from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from models import baseModel
import os
import subprocess
from urllib import parse
import re
import config.config


class nmapModel(baseModel.baseModel):

    def __init__(self, name) -> None:
        super().__init__(name)
        self.log_path =self.log_dir + "nmap_log.txt"
        self.log_dir = self.log_dir + "nmap\\"

        if(os.path.exists(self.log_dir)):
            pass
        else:
            os.mkdir(self.log_dir)
    

    def checkRequest(self, flow: HTTPFlow):
        super().checkRequest(flow)

        url:str = flow.request.url

        hostname = parse.urlparse(url).netloc

        if self.urls.get(hostname):
            return
        
        self.urls[hostname] = True

        method:str = flow.request.method
        cmd = "nmap \"" + hostname + '\"' 

        log_file = self.log_dir + str(self.log_idx) + ".txt"
        self.log_idx += 1

         # like: nmap example.com

        ctx.log.info("nmap checking... " + hostname+"\n")

        with open(log_file, '+a') as fp:
            p = subprocess.Popen(cmd,stdin=subprocess.PIPE, stdout=fp, stderr=subprocess.PIPE)
            return_code = p.wait()

        res = self.handle_log(log_file, hostname)
        if res:
            ctx.log.info("nmap checked! " + hostname + "\n")
        else:
            self.REPORT("nmap checked! Potentially vulnerable ports found: " + hostname + "\n" + "!!!!!!!!Please check the log: " + log_file + '\n')

    def handle_log(self, f_name: str, url: str):
        lines = None
        out = " "
        res = True

        with open(f_name,'r+') as fp:
            lines = fp.readlines()

        pa = "([0-9]*)/.* open *(.*)"

        for line in lines:
            mtch = re.match(pa, line)
            if mtch!=None:
                g_mtch = mtch.groups()
                if len(g_mtch) >= 2 and config.config.RISK_PORT.issuperset({int(g_mtch[0]),}):
                    res = False
                    out = "nmap: Potentially vulnerable ports found at the following URL: " + url + " port: " + g_mtch[0] + ' ' + g_mtch[1]
                    self.REPORT(out)
        
        return res

        