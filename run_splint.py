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
        cmd = "splint -warnposix +posixlib +csvoverwrite +trytorecover -csv %s %s" %(os.path.join(output_path, output_file), testcase.testcase_dir_abs)
        return cmd

    def _parseOutput(self, testcase, output_path, output_file="result.xml"):
        bugs = []
        xml_in = open(os.path.join(output_path, output_file))
        tree = ET.parse(xml_in)
        root = tree.getroot()
        for vulnerability_node in root.findall("vulnerability"):
            bug = Bug()
            bug.testcase_id = testcase.testcase_id
            bug.bug_type = vulnerability_node.findall("type")[0].text
            bug.description = vulnerability_node.findall("message")[0].text

            file_node = vulnerability_node.findall("file")[0]
            # 记录sink点
            bug.sink.file = file_node.findall("name")[0].text.replace("//", "/").split(testcase.testcase_dir)[-1].strip("/")
            bug.sink.line = int(file_node.findall("line")[0].text)
            bugs.append(bug)
        xml_in.close()
        return bugs

if __name__ == "__main__":
    pass