# -*- coding=utf-8 -*-
import os, sys, zipfile, shutil
sys.path.append("..")
from glo import *
from bug import *
import juliet_parser

tool = os.path.join(Config.LIBS, "tooling_sample")
f_fun_info = os.path.join(Config.TMP, "func_line.info")

# gen function line info using libtooling
def gen_func_info(sourcefile):
    # -DINCLUDEMAIN 是为了适配juliet的编译而增加的预定义宏
    cmd = "%s %s -extra-arg=\"-DINCLUDEMAIN -I%s\" > %s 2>/dev/null"%(tool, sourcefile, os.path.dirname(sourcefile), f_fun_info)
    os.system(cmd)
    f = open(f_fun_info)
    lines = f.readlines()
    f.close()
    return lines

def parse_func_info(lines, filters=[]):
    # {
    #  filename: 
    #  {fun_name1: (startline, endline), fun_name2: (startline, endline)}
    # }
    info = {}
    for line in lines:
        funname = line.split("#")[0]
        funinfo = line.split("#")[1]
        if funinfo.find("/usr") > 0:
            continue
        for one in filters:
            if funinfo.find(one) < 0:
                continue
        funinfo = funinfo.split(":")
        filepath = funinfo[1]
        if filepath not in info.keys():
            info[filepath] = {}
        if funname not in info[filepath].keys():
            info[filepath][funname] = {}
        linenum = funinfo[2]
        info[filepath][funname][funinfo[0]] = linenum
    return info

