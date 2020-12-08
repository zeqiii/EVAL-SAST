# -*- coding=utf-8 -*-
import os, sys, csv
from impl import *
from glo import *
from bug import *

class Runner_uno(Runner):
    def __init__(self):
        Runner.__init__(self)
        self.tool = "uno"

    def _genCMD(self, testcase, output_path, output_file="result.out"):
        if not os.path.exists(testcase.testcase_dir_abs):
            raise Exception(testcase.testcase_dir_abs + " does not exist")
        build_command = ""
        # 根据不同的测试集，实现不同的编译方法
        # uno
        if not os.path.exists(output_path):
            os.makedirs(output_path) # 对于splint，需要我们来创建存放检测结果的文件夹
        # 检测结果存放在result.xml文件中
        cmd = "uno %s/*.c > %s" %(testcase.testcase_dir_abs, os.path.join(output_path, output_file))
        return cmd

    def _parseOutput(self, testcase, output_path, output_file="result.out"):
        bugs = []
        with open(os.path.join(output_path, output_file)) as fp:
            line = ""
            while True:
                line = fp.readline()
                if line == None or line.find("check completed") >= 0:
                    break
                if line.find("uno:") > 0:
                    line2 = fp.readline()
                    line3 = fp.readline()
                    if not (line2.strip().startswith("statement") and line3.strip().startswith("declaration")):
                        continue
                    bug = Bug()
                    bug.testcase_id = testcase.testcase_id
                    line = line.strip().lstrip("uno:").strip()
                    bug.description = line.split(":")[2].strip()
                    bug.sink.file = line.split(":")[0].split(testcase.testcase_dir)[-1].strip("/")
                    bug.sink.line = int(line.split(":")[1].strip())
                    bugs.append(bug)
        return bugs

if __name__ == "__main__":
    pass
