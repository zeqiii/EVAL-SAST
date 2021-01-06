# -*- coding=utf-8 -*-
import os, sys, argparse
sys.path.append("..")
from glo import *
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

# 用一种简单暴力的方式标注目标程序中的反例所在位置
# keywords = {signature: keyword}
def mark_counterexamples(in_dir, keywords):
    for parent, dirs, files in os.walk(in_dir):
        for f in files:
            # 除去testcasesupport文件
            if f in Global.JULIET_TESTCASESUPPORT:
                continue
            ff = os.path.join(parent, f)
            altered = False
            with open(ff, "r") as fp:
                content = fp.readlines()
            for key in keywords.keys():
                if ff.find(key) >= 0:
                    keyword = keywords[key]
                    for i in range(0, len(content)):
                        if content[i].find(keyword) >= 0 and content[i].find("##bug##") < 0 \
                                and content[i].find("##counterexample##")< 0:
                            content[i] = content[i].rstrip() + " /* ##counterexample## */\n"
                            altered = True
            if altered:
                with open(ff, "w") as fp:
                    new_content = ""
                    for line in content:
                        new_content = new_content + line
                    fp.write(new_content)




if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', help="path of the test suite")
    # 记录关键字的文件，每行中，@@左边为目标程序种类，@@右边为该类目标程序中反例的关键词
    parser.add_argument('--keywords', '-k', help="path of file that stores the keywords of counterexamples")
    args = parser.parse_args()
    if not args.keywords or not args.input:
        print("no input or keywords!")
        exit(1)
    keywords = {}
    with open(args.keywords) as fp:
        content = fp.readlines()
        for one in content:
            key = one.split("@@")[0].strip()
            value = one.split("@@")[1].strip()
            keywords[key] = value

    mark_counterexamples(args.input, keywords)