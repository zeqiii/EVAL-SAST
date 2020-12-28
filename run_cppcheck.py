# -*- coding=utf-8 -*-
import os, sys
import xml.etree.ElementTree as ET
from impl import *
from glo import *
from bug import *

class Runner_cppcheck(Runner):
    def __init__(self):
        Runner.__init__(self)
        self.tool = "cppcheck"

    def _genCMD(self, testcase, output_path, output_file="result.xml"):
        if not os.path.exists(testcase.testcase_dir_abs):
            raise Exception(testcase.testcase_dir_abs + " does not exist")
        build_command = ""
        # 根据不同的测试集，实现不同的编译方法
        # cppcheck不需要实现编译
        if not os.path.exists(output_path):
            os.makedirs(output_path) # 对于cppcheck，需要我们来创建存放检测结果的文件夹
        # 检测结果存放在result.xml文件中
        cmd = "cppcheck --xml --enable=warning %s 2> %s" %(testcase.testcase_dir_abs, os.path.join(output_path, output_file))
        return cmd

    def _parseOutput(self, testcase, output_path, output_file="result.xml"):
        bugs = []
        xml_in = open(os.path.join(output_path, output_file))
        tree = ET.parse(xml_in)
        root = tree.getroot()
        errors_nodes = root.findall("errors")
        error_nodes = []
        for errors_node in errors_nodes:
            error_nodes.extend(errors_node.findall("error"))
        for error_node in error_nodes:
            bug = Bug()
            bug.testcase_id = testcase.testcase_id
            bug.bug_type = error_node.attrib['id']
            bug.description = error_node.attrib['verbose']
            if 'cwe' in error_node.attrib.keys():
                bug.cwe_type.append("CWE-%s"%(error_node.attrib['cwe']))
            location_nodes = error_node.findall("location")
            if not location_nodes:
                continue
            # 记录sink点
            bug.sink.file = location_nodes[0].attrib['file'].split(testcase.testcase_dir)[-1].strip('/')
            bug.sink.line = int(location_nodes[0].attrib['line'])
            # 记录source点
            if len(location_nodes) >= 2:
                bug.source.file = location_nodes[-1].attrib['file'].split(testcase.testcase_dir)[-1].strip('/')
                bug.source.line = int(location_nodes[-1].attrib['line'])
            # 记录execution_path
            if len(location_nodes) > 2:
                for i in range(1, len(location_nodes)-1):
                    location = Location()
                    location.file = location_nodes[i].attrib['file'].split(testcase.testcase_dir)[-1].strip('/')
                    location.line = int(location_nodes[i].attrib['line'])
                    bug.execution_path.append(location)
            bugs.append(bug)
        xml_in.close()
        return bugs

if __name__ == "__main__":
    pass
