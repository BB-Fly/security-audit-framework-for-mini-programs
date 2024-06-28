from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from models import baseModel
import os
import subprocess
from urllib import parse
import re
import json


class XSSModel(baseModel.baseModel):

    def __init__(self, name) -> None:
        super().__init__(name)
        self.log_path =self.log_dir + "xss_log.txt"
        self.log_dir = self.log_dir + "xss\\"

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

        method:str = flow.request.method
        cmd_pre = self.python_cmd + self.tools_path + "\\XSStrike\\xsstrike.py "
        cmd = None
        if method == "GET":
            cmd = cmd_pre + " -u \"" + url + "\" --skip"
        elif method == "POST":
            url_parse = parse.urlparse(url)
            url_pre =  url_parse.scheme + "://" + url_parse.netloc + url_parse.path
            url_data = " "
            if url_parse.query:
                url_data =  url_parse.query
                cmd = cmd_pre + " -u \"" + url_pre + "\" " + "--data \"" + url_data +'\" --skip'
            else:
                body = json.loads(flow.request.get_text())
                url_data = json.dumps(body)
                cmd = cmd_pre + " -u \"" + url_pre + "\" " + "--json \"" + url_data +'\" --skip'
        else:
            ctx.log.warn("xss checking with method: " + method + "\n url = " + url)
            return

         # like: python xsstrike.py -u "http://example.com/search.php?q=query" --skip

        ctx.log.info("xss checking... " + url+"\n")

        log_file = self.log_dir + str(self.log_idx) + ".txt"
        self.log_idx += 1
        with open(log_file, '+a') as fp:
            p = subprocess.Popen(cmd,stdin=subprocess.PIPE, stdout=fp, stderr=subprocess.PIPE)
            return_code = p.wait()
        res = self.handle_log(log_file, url)
        if res:
            ctx.log.info("xss checked! " + url + "\n")
        else:
            self.REPORT("xss checked, Potentially vulnerable objects found: " + url + "\n" + "!!!!!!!!Please check the log: " + log_file + '\n')


    def handle_log(self, f_name:str, url:str):
        lines:str = None

        stat = "None"
        out = " "

        res = True

        with open(f_name, 'r+') as fp2:
            lines = fp2.readlines()
        
        for line in lines:
            if line.find("Checking for DOM vulnerabilities") >= 0:
                stat = "DOM"
            elif line.find("Testing parameter") >= 0:
                pa = ".*Testing parameter: (.*) .*"
                mtch = re.match(pa, line)
                if mtch!=None:
                    stat = mtch[1]
            elif line.find("Potentially vulnerable objects found") >= 0:
                res = False
                out = "xsstrike:Potentially vulnerable objects found, url: " + url + "\n"
                self.REPORT(out)
            elif line.find("Reflections found:") >= 0:
                res = False
                out = line + "with testing parameter: "+stat + " url:" + url + '\n'
                self.REPORT(out)

        return res
    