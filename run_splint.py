# -*- coding=utf-8 -*-
import os, sys, csv
from impl import *
from glo import *
from bug import *

class Runner_splint(Runner):
    def __init__(self):
        Runner.__init__(self)
        self.tool = "splint"

    def _genCMD(self, testcase, output_path, output_file="result.xml"):
        if not os.path.exists(testcase.testcase_dir_abs):
            raise Exception(testcase.testcase_dir_abs + " does not exist")
        build_command = ""
        # 根据不同的测试集，实现不同的编译方法
        # splint
        if not os.path.exists(output_path):
            os.makedirs(output_path) # 对于splint，需要我们来创建存放检测结果的文件夹
        # 检测结果存放在result.xml文件中
        cmds = []
        index = 0
        for parent, dirs, files in os.walk(testcase.testcase_dir_abs):
            for f in files:
                cmds.append("splint -warnposix -syntax +csvoverwrite +trytorecover -csv %s %s" %(os.path.join(output_path, "result%d.csv"%(index)), os.path.join(parent, f)))
                index = index + 1
        cmd = ""
        for one in cmds:
            cmd = cmd + one + ";"
        cmd = cmd.rstrip(";")
        return cmd

    def _parseOutput(self, testcase, output_path, output_file="result.xml"):
        bugs = []
        for parent, dirs, files in os.walk(output_path):
            for f in files:
                with open(os.path.join(parent, f)) as fp:
                    reader = csv.reader(fp)
                    content = list(reader)
                    if len(content) < 1:
                        continue
                    for i in range(1, len(content)):
                        bug = Bug()
                        bug.testcase_id = testcase.testcase_id
                        bug.bug_type = content[i][2]
                        bug.description = content[i][8]
                        bug.sink.file = content[i][4].split(testcase.testcase_dir)[-1].strip("/")
                        bug.sink.line = int(content[i][5])
                        bug.sink.col = int(content[i][6])
                        bugs.append(bug)
        return bugs

if __name__ == "__main__":
    pass
