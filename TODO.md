
#### 一阶段 集成，能跑就行 任务清单：
|模块名|开发进度|完成情况|备注|
|:---:|:---:|:---:|:---:|
| XSStrike  | 扫描检测完成  |       $\color{00FF00}{完成}$|py库 |
|XSSor2         |     ？不懂      |         $\color{004402}{更换工具}$|bolt
autoSSRF          |   限制系统   |            $\color{004402}{更换工具}$| ZAP 
semgrep           |         |    $\color{004402}{更换工具}$                  |ZAP
CRLF-injection-scanner   |   完成     |         $\color{00FF00}{完成}$|py库 
sqlmap                 |     扫描检测完成  |    $\color{00FF00}{完成}$|py库，需要配置项
fuxploider           |       完成       |  $\color{00FF00}{完成}$|py库 
afrog                |       完成|$\color{00FF00}{完成}$|不同系统有差别
ZAP| 完成|$\color{00FF00}{完成}$|难集成，正在研究
Dirsearch|完成|$\color{00FF00}{完成}$|
nmap|完成|$\color{00FF00}{完成}$| 需要程序判断哪些端口有危险
bolt|完成|$\color{00FF00}{完成}$|




$\color{00FF00}{完成}$
$\color{FF7D00}{待测试}$
$\color{FF0000}{未完成}$
$\color{004402}{更换工具}$



#### 二阶段 统一输出格式 任务清单：
|模块名|检测项|完成情况|备注|
|:---:|:---:|:---:|:---:|
| XSStrike  |  DOM-XSS Reflection-XSS |   $\color{00FF00}{完成}$    |     
CRLF-injection-scanner   |   CRLF     |        $\color{00FF00}{完成}$ 
sqlmap                 |    sql注入   |   $\color{00FF00}{完成}$|
fuxploider           |        任意文件上传      | $\color{00FF00}{完成}$
afrog                |  任意文件包含     |$\color{00FF00}{完成}$
ZAP|多种通用检测项 |$\color{00FF00}{完成}$|操作略繁琐，需要改进
Dirsearch|敏感路径|$\color{00FF00}{完成}$
nmap|敏感端口|$\color{00FF00}{完成}$
bolt|CSRF|$\color{00FF00}{完成}$


#### 三阶段 测试 任务清单：
|模块名|检测项|完成情况|备注|
|:---:|:---:|:---:|:---:|
| XSStrike  |  DOM-XSS Reflection-XSS |   $\color{00FF00}{完成}$  | 
CRLF-injection-scanner   |   CRLF     |        $\color{00FF00}{完成}$
sqlmap                 |       |  $\color{00FF00}{完成}$  |
fuxploider           |              | $\color{00FF00}{完成}$
afrog                |       |$\color{00FF00}{完成}$
ZAP| |$\color{00FF00}{完成}$
Dirsearch||$\color{00FF00}{完成}$
nmap||$\color{00FF00}{完成}$
bolt|CSRF|$\color{00FF00}{完成}$