### 如何启动项目

__1. 安装py包__

    pip3 install mitmproxy

    其余包需求参考相关开源工具

__2. 安装开源软件__

    开源工具列表：
    XSStrike  https://github.com/s0md3v/XSStrike
    sqlmap  https://sqlmap.org/
    dirsearch  https://github.com/maurosoria/dirsearch
    ZAP  https://www.zaproxy.org/
    fuxploider  https://github.com/almandin/fuxploider
    bolt  https://github.com/s0md3v/Bolt
    nmap  https://nmap.org/man/zh/
    CRLF-Injection-Scanner  https://github.com/MichaelStott/CRLF-Injection-Scanner
    afrog  https://github.com/zan8in/afrog

    除ZAP外，其余所有工具需要安装在 /tools 目录下


__3. 修改配置文件__

    config文件夹下有配置文件
    需要用户根据情况修改
__4. 运行脚本__

    >> mitmdump -s ./main.py

__5.测试结果__

    如果发现任何潜在的危险，会直接输出在终端。同时main/logs文件夹下会生成reports.txt文件，汇总全部错误信息

    对于每个类型的扫描项，都会生成一个文件夹，内含一定数量的文件。每个文件记录了对某个url的扫描结果。同时，会另外生成一个文件汇总错误信息。

    以XSS检测项为例。假定共扫描了10个url，其中有3个发现潜在危险。
    会生成3条错误信息，汇总记录在xss.txt文件内。
    同时，每个url都会有在xss文件夹下有一个文件，共10个独立的文件，记录完整的扫描信息。
    而在report.txt文件内，也会记录这3条错误信息。

