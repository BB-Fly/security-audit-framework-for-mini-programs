import re
from mitmproxy import http
from multiprocess.pool import ThreadPool
from models import *
import config.config


class Scanner:

    config_path = "./c"


    def _config(self, prop:list[str]):
        if(prop==None):
            # TODO: load from config file
            self.prop = [

            ]
        else:
            self.prop = {}
            for it in prop:
                self.prop[it] = True

        


    def __init__(self, name:str = None, prop:set[str] = None):
        if name == None:
            name = "None"
        self.appName = name
        self._config(prop)
        self.checkModels:list[baseModel.baseModel] = []
        self.urls:dict = {}

        self.pool = ThreadPool(config.config.THREAD_NUM)

        # TODO: 每当添加新的模块时，在此后续
        if "XSS" in self.prop:
            self.checkModels.append(XSSModel.XSSModel(name))
        if "sqlmap" in self.prop:
            self.checkModels.append(sqlmapModel.sqlmapModel(name))
        if "fuxploider" in self.prop:
            self.checkModels.append(fuxploiderModel.fuxploiderModel(name))
        if "CRLF" in self.prop:
            self.checkModels.append(CRLFModel.CRLFModel(name))
        if "afrog" in self.prop:
            self.checkModels.append(afrogModel.afrogModel(name))
        if "dirsearch" in self.prop:
            self.checkModels.append(dirsearchModel.dirsearchModel(name))
        if "ZAP" in self.prop:
            self.checkModels.append(ZAPModel.ZAPModel(name))
        if "nmap" in self.prop:
            self.checkModels.append(nmapModel.nmapModel(name))
        if "bolt" in self.prop:
            self.checkModels.append(boltModel.boltModel(name))


    @staticmethod
    def _apply(mod:baseModel.baseModel, flow, is_request):
        if is_request:
            return mod.checkRequest(flow)
        else:
            return mod.checkResponse(flow)



    def _checkFlow(self, flow:http.HTTPFlow)->bool:
        if(self.appName==None or self.appName=="None"):
            return True
        
        url = flow.request.url
        if bool(re.search(self.appName, url)) :
            return True
        else:
            return False


    def request(self, flow:http.HTTPFlow):

        if not self._checkFlow(flow):
            return
        url:str = flow.request.url

        if self.urls.get(url):
            return
        if config.config.MAX_URL > 0 and len(self.urls) > config.config.MAX_URL:
            return
        self.urls[url] = True
        urls_path = self.checkModels[0].url_path
        with open(urls_path, '+a') as fp:
            fp.write(url+'\n')

        for mod in self.checkModels:
            self.pool.apply_async(self._apply, args=(mod, flow, True,))


    def response(self, flow:http.HTTPFlow):
        # if not self._checkFlow(flow):
        #     return

        # for mod in self.checkModels:
        #     self.pool.apply_async(Scanner._apply, args=(mod, flow, False))  
        pass


    def check_urls(self):
        for mod in self.checkModels:
            mod.check_urls()