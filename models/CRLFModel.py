from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from models import baseModel
import os
import subprocess
from urllib import parse


class CRLFModel(baseModel.baseModel):

    def __init__(self, name) -> None:
        super().__init__(name)
        self.log_path =self.log_dir + "CRLF_log.txt"
        self.log_dir = self.log_dir + "crlf\\"

        if(os.path.exists(self.log_dir)):
            pass
        else:
            os.mkdir(self.log_dir)
    

    def checkRequest(self, flow: HTTPFlow):
        super().checkRequest(flow)

        url:str = flow.request.url

        url_parse = parse.urlparse(url)
        url_pre =  url_parse.scheme + "://" + url_parse.netloc

        if self.urls.get(url_pre):
            return
        
        self.urls[url_pre] = True

        method:str = flow.request.method
        cmd_pre = self.python_cmd + self.tools_path + "\\CRLF-Injection-Scanner\\crlf.py "
        cmd = cmd_pre + " scan -u \"" + url_pre + "\""

        #like: python crlf scan -u "www.google.com"

        log_file = self.log_dir + str(self.log_idx) + ".txt"
        self.log_idx += 1


        ctx.log.info("CRLF checking... " + url_pre+"\n")

        with open(log_file, '+a') as fp:
            p = subprocess.Popen(cmd,stdin=subprocess.PIPE, stdout=fp, stderr=subprocess.PIPE)
            return_code = p.wait()

        res = self.handle_log(log_file, url_pre)
        if res:
            ctx.log.info("CRLF checked! " + url_pre + "\n")
        else:
            self.REPORT("CRLF checked! Potentially vulnerable objects found: " + url_pre + "\n" + "!!!!!!!!Please check the log: " + log_file + '\n')


    def handle_log(self, f_name: str, url:str):
        lines = None
        out = " "
        res = True

        with open(f_name,'r+') as fp:
            lines = fp.readlines()

        for line in lines:
            if line.find("CRLF injection detected at the following URLs") >= 0:
                res = False
                out = "CRLF injection detected at the following URL: " + url
                self.REPORT(out)
        
        return res