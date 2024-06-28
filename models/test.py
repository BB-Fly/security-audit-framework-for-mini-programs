import zapv2
import time
import pprint


url = "https://www.bilibili.com/v/popular/all/?spm_id_from=333.1007.0.0"

apikey = "e1u3j03k7r8f7bsmaa60c2epse"

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

zap = zapv2.ZAPv2(apikey=apikey , proxies=proxies)
sId = zap.spider.scan(url)

while int(zap.spider.status(sId)) < 100:
    time.sleep(2)

results =  zap.core.alerts(baseurl=url)

for result in results:
    pprint.pprint(result)

pass
