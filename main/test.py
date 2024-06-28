import time
import zapv2


ZAP_PROXY = {
            'http': 'http://127.0.0.1:8080',
            'https': 'http://127.0.0.1:8080'
        }
ZAP_APIKEY = "e1u3j03k7r8f7bsmaa60c2epse"

class A:

    def __init__(self) -> None:
        self.apikey = ZAP_APIKEY
        self.proxies = ZAP_PROXY

        self.zap = zapv2.ZAPv2(apikey=self.apikey , proxies=self.proxies)

    def check_urls(self):
        
        urls = None

        with  open("main\\logs\\urls.txt", 'r+') as fp:
            urls = fp.readlines()

            log_idx = 0

        for url in urls:
            print("zap checking... " + url+"\n")

            log_file = "main\\logs\\" + str(log_idx) + ".txt"
            log_idx += 1
            sId = self.zap.spider.scan(url)

            while int(self.zap.spider.status(sId)) < 100:
                time.sleep(2)

            time.sleep(5)

            sId = self.zap.ascan.scan(url)
            while int(self.zap.ascan.status(sId)) < 100:
                print(self.zap.ascan.status(sId) + '\n')
                time.sleep(2)
                
            results =  self.zap.core.alerts(baseurl=url)
            with open(log_file, '+a') as fp:
                for result in results:
                    fp.write(result)

            res = self.handle_log(log_file, url)
            if res:
                print("zap checked! " + url + "\n")
            else:
                print("zap: file upload vulnerability found at the following URL: " + url + "\n" + "!!!!!!!!Please check the log: " + log_file + '\n')


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
                print(out)

        return res
    

if __name__ == "__main__":
    a = A()
    a.check_urls()