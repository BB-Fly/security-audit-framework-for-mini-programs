from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from models import baseModel
import os
import subprocess


class fuxploiderModel(baseModel.baseModel):

    def __init__(self, name) -> None:
        super().__init__(name)
        self.log_path =self.log_dir + "fuxploider_log.txt"
        self.log_dir = self.log_dir + "fuxploider\\"

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

        cmd_pre = self.python_cmd + self.tools_path + "\\fuxploider\\fuxploider.py "
        cmd = cmd_pre + " --url \"" + url + "\" --not-regex \"wrong file type\""

        # like python fuxploider.py --url "https://www.csdn.net/" --not-regex "wrong file type"

        log_file = self.log_dir + str(self.log_idx) + ".txt"
        self.log_idx += 1

        ctx.log.info("fuxploider checking... " + url+"\n")

        with open(log_file, '+a') as fp:
            p = subprocess.Popen(cmd,stdin=subprocess.PIPE, stdout=fp, stderr=subprocess.PIPE)
            return_code = p.wait()

        res = self.handle_log(log_file, url)
        if res:
            ctx.log.info("fuxploider checked! " + url + "\n")
        else:
            self.REPORT("fuxploider: file upload vulnerability found at the following URL: " + url + "\n" + "!!!!!!!!Please check the log: " + log_file + '\n')


    def handle_log(self, f_name: str, url: str):
        res = True

        out = " "
        lines = None

        with open(f_name, 'r+') as fp:
            lines = fp.readlines()

        for line in lines:
            if line.find("Found the following entry points:") >= 0:
                res = False
                out = "fuxploider: file upload vulnerability found at the following URL: " + url
                self.REPORT(out)

        return res