# -*- coding=utf-8 -*-
import os, sys, argparse
sys.path.append("..")
from glo import *

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass
    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass 
    return False

# 从Juliet的文件名中提取测试样本名，如CWE114_Process_Control__w32_char_connect_socket_07.c 提取 CWE114_Process_Control__w32_char_connect_socket
# signature可以看作是目标程序的种类
def getSignature(filename):
    part_2 = filename.split("_")[-1]
    if part_2.startswith("good") or part_2.startswith("bad"):
        part_2 = filename.split("_")[-2]
    num = ""
    for index in range(0, len(part_2)):
        if is_number(part_2[index]):
            num = num + part_2[index]
        else:
            break
    signature = filename.split("_"+num)[0]
    return signature

# 用一种简单暴力的方式标注目标程序中的反例所在位置
# keywords = {signature: keyword}
def mark_counterexamples(in_dir, keywords):
    for parent, dirs, files in os.walk(in_dir):
        for f in files:
            # 除去testcasesupport文件
            if f in Global.JULIET_TESTCASESUPPORT:
                continue

            signature = getSignature(f)
            if signature not in keywords.keys(): # 没有反例/不设反例/不关注该类目标程序的反例
                continue

            ff = os.path.join(parent, f)
            altered = False
            content = []

            with open(ff, "r") as fp:
                content = fp.readlines()

            if signature not in keywords.keys():
                continue

            keyword = keywords[signature]
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
            one = one.strip()
            if not one:
                continue
            key = one.split("@@")[0].strip()
            value = one.split("@@")[1].strip()
            keywords[key] = value

    print(keywords)
    mark_counterexamples(args.input, keywords)
