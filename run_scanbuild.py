# -*- coding=utf-8 -*-
import os, sys, subprocess, codecs
from impl import *
from glo import *
from bug import *
from xml import etree

class Runner_scanbuild(Runner):
    def __init__(self):
        Runner.__init__(self)
        self.tool = "scan-build"

    def _genCMD(self, testcase, output_path, output_file="result.out"):
        if not os.path.exists(testcase.testcase_dir_abs):
            raise Exception(testcase.testcase_dir_abs + " does not exist")
        build_command = ""
        # 根据不同的测试集，实现不同的编译方法
        if testcase.testsuite_name == 'juliet':
            build_command = testcase.compile_command
        cmd = "cd %s && scan-build -o %s %s" %(testcase.testcase_dir_abs, output_path, build_command)
        return cmd

    def _parseOutput(self, testcase, output_path, output_file="result.out"):
        p = subprocess.check_output("cd " + output_path + ";ls -l|grep '^d'|awk '{print $9}'|grep '2*'", shell=True)
        p = p.split("\n")
        path = output_path + "/" + p[0] + "/index.html"
        f = codecs.open(path, "r", "utf-8")
        content = f.read()
        f.close()
        tree = etree.HTML(content)
        nodes = tree.xpath("//tbody//tr//td/text()")
        urls = tree.xpath("//tbody//tr/td[7]/a/@href")
        ds = []
        for url in urls:
            url = url[:-8]
            f = codecs.open(output_path+"/"+p[0]+"/"+url, "r", "utf-8")
            con = f.read()
            f.close()
            t = etree.HTML(con)
            des = t.xpath("//table[@class='simpletable']/tr[3]/td[2]/text()")
            ds.append(des)
        t = 0
        bugs = []
        print(nodes)
        for i in range(0,len(nodes),6):
            b = nodes[i:i+6]
            bug = Bug()
            bug.bug_type = b[1]
            bug.method =b[3]
            bug.vul_path.append({"filename":b[2], "line":b[4]})
            bug.description=ds[t][0]
            t=t+1
            bug_list.append(bug)
        
        return bugs

if __name__ == "__main__":
    json_file = sys.argv[1]
    outputReader(json_file)
