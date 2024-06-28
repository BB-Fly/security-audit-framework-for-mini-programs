# coding=utf-8 #

import sys
import os


current_directory = os.path.dirname(os.path.abspath(__file__)).replace("\\main", "")
sys.path.append(current_directory)
from models.Scanner import Scanner

"""
不设置name参数时, 即可对所有包进行扫描
"""
addons = [
    Scanner(
        # name = "docin",
        # name = "csdn",
        # name = "meituan",
        prop = [
                "XSS",
                "sqlmap",
                "fuxploider",
                "CRLF",
                "afrog",
                "dirsearch",
                "ZAP",
                "nmap",
                "bolt",
                ],
    )
]

pass

# 使用方式: mitmdump -s ./main.py

"""
也可以不用scanner,
像下面一样直接使用不同的扫描模块,
但这样可能因为没有进程池的管理, 导致太多进程影响效率
"""

# addons = [
#     XSSModel.XSSModel(),
#     sqlmapModel.sqlmapModel(),
#     fuxploiderModel.fuxploiderModel(),
# ]