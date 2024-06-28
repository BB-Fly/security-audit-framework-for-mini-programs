from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from models import baseModel
import os
import subprocess
from urllib import parse
import json


class sqlmapModel(baseModel.baseModel):

    def __init__(self, name) -> None:
        super().__init__(name)
        self.log_path =self.log_dir + "sqlmap_log.txt"
        self.log_dir = self.log_dir + "sqlmap\\"

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
        cmd_pre = self.python_cmd + self.tools_path + "\\sqlmap\\sqlmap.py "
        cmd = ""

        if method == "GET":
            cmd = cmd_pre + " -u \"" + url + "\" -v 3"
        elif method == "POST":
            url_parse = parse.urlparse(url)
            url_pre =  url_parse.scheme + "://" + url_parse.netloc + url_parse.path
            url_data = " "
            if url_parse.query:
                url_data =  url_parse.query
                cmd = cmd_pre + " -u \"" + url_pre + "\" " + "--data=\"" + url_data +'\" -v 3'
            else:
                body = json.loads(flow.request.get_text())
                url_data = json.dumps(body)
                cmd = cmd_pre + " -u \"" + url_pre + "\" " + "--data=\"" + url_data +'\" -v 3'
        else:
            ctx.log.warn("xss checking with method: " + method + "\n url = " + url)
            return

        # like: python sqlmap.py -u "http://example.com/search.php?q=query"  -v 3

        ctx.log.info("sqlmap checking... " + url+"\n")

        log_file = self.log_dir + str(self.log_idx) + ".txt"
        self.log_idx += 1

        with open(log_file, '+a') as fp:
            with subprocess.Popen(cmd,stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8") as proc:
                try:
                    stdin = proc.stdin
                    while True:
                        tmp_line = proc.stdout.readline()
                        if not tmp_line and proc.returncode is not None:
                            break
                        str_line = str(tmp_line)+"\n"
                        fp.write(str_line)
                        if "[Y/n]" in str_line:
                            stdin.write("y\n")
                            stdin.flush()
                        elif "(C)ontinue" in str_line:
                            stdin.write("c\n")
                            stdin.flush()
                        elif "Enter" in str_line:
                            stdin.write("\n")
                            stdin.flush()
                        elif "ending" in str_line:
                            break
                            
                except TimeoutError:
                    proc.kill()

        ctx.log.info("sqlmap checked! " + url + "\n")

        res = self.handle_log(log_file, url)

        if res:
            ctx.log.info("sqlmap checked! " + url + "\n")
        else:
            self.REPORT("sqlmap: vulnerability found at the following URL: " + url + "\n" + "!!!!!!!!Please check the log: " + log_file + '\n')



    def handle_log(self, f_name: str, url: str):
        res = True

        out = " "
        lines = None

        with open(f_name, 'r+') as fp:
            lines = fp.readlines()

        for line in lines:
            if line.find("reflective value(s) found") >= 0:
                res = False

            out = "sqlmap: vulnerability found at the following URL: " + url
            self.REPORT(out)
        
        return res