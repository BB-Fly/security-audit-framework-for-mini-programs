from mitmproxy.http import HTTPFlow
from mitmproxy import ctx
from models import baseModel
import os
import zapv2
import time
from urllib import parse
import config.config


class ZAPModel(baseModel.baseModel):

    def __init__(self, name) -> None:
        super().__init__(name)
        self.log_path =self.log_dir + "ZAP_log.txt"
        self.log_dir = self.log_dir + "zap\\"

        self.apikey = config.config.ZAP_APIKEY
        self.proxies = config.config.ZAP_PROXY

        self.zap = zapv2.ZAPv2(apikey=self.apikey , proxies=self.proxies)

        if(os.path.exists(self.log_dir)):
            pass
        else:
            os.mkdir(self.log_dir)


    def check_urls(self):
        
        urls = None

        with  open(self.url_path, 'r+') as fp:
            urls = fp.readlines()

        for url in urls:
            ctx.log.info("zap checking... " + url+"\n")

            log_file = self.log_dir + str(self.log_idx) + ".txt"
            self.log_idx += 1
            self.zap.urlopen(url)

            sId = self.zap.spider.scan(url)
            while int(self.zap.spider.status(sId)) < 100:
                time.sleep(2)
            time.sleep(5)

            sId = self.zap.ascan.scan(url)
            while int(self.zap.ascan.status(sId)) < 100:
                time.sleep(2)
                
            results =  self.zap.core.alerts(baseurl=url)
            with open(log_file, '+a') as fp:
                for result in results:
                    fp.write(result)

            res = self.handle_log(log_file, url)
            if res:
                ctx.log.info("zap checked! " + url + "\n")
            else:
                self.REPORT("zap: file upload vulnerability found at the following URL: " + url + "\n" + "!!!!!!!!Please check the log: " + log_file + '\n')


    def handle_log(self, f_name: str, url: str):
        res = True

        out = " "
        lines = None

        with open(f_name, 'r+') as fp:
            lines = fp.readlines()

        for line in lines:
            if line.find("Found the following entry points:") >= 0:
                res = False
                out = "zap: file upload vulnerability found at the following URL: " + url
                self.REPORT(out)

        return res