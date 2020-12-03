# -*- coding=utf-8 -*-
import os, sys, re
from impl import *
from glo import *
from bug import *

class Runner_flawfinder(Runner):
    def __init__(self):
        Runner.__init__(self)
        self.tool = "flawfinder"
        p = subprocess.check_output("flawfinder --listrules", shell=True)
        self.flawfinder_rules = {}
        self.__parse_rules(bytes.decode(p))  # flawfinder检测规则名称和描述

    def __parse_rules(self, raw):
        lines = raw.split("\n")
        for line in lines:
            parts = line.split("\t")
            self.flawfinder_rules[parts[0]] = parts[2]

    def _genCMD(self, testcase, output_path, output_file="result.out"):
        if not os.path.exists(testcase.testcase_dir_abs):
            raise Exception(testcase.testcase_dir_abs + " does not exist")
        build_command = ""
        # 根据不同的测试集，实现不同的编译方法
        # flawfinder不需要实现编译
        if not os.path.exists(output_path):
            os.makedirs(output_path) # 对于flawfinder，需要我们来创建存放检测结果的文件夹
        # 检测结果存放在result.out文件中
        cmd = "flawfinder -C %s > %s" %(testcase.testcase_dir_abs, os.path.join(output_path, output_file))
        return cmd

    def _parseOutput(self, testcase, output_path, output_file="result.out"):
        bugs = []
        f = open(os.path.join(output_path, output_file), "r")
        linetext = f.readline()
        while linetext.find("FINAL RESULTS:") < 0:
            linetext = f.readline()
            if not linetext:
                f.close()
                return bugs
        while linetext.find("ANALYSIS SUMMARY:") < 0:
            linetext = f.readline()
            if len(linetext.strip()) == 0:
                continue
            if linetext.startswith("  "):
                continue
            bug = Bug()
            bug_location = linetext.split("  ")[0]
            bug_type = linetext.split("  ")[1]
            parts = bug_location.split(":")
            bug.sink.file = parts[0].split(testcase.testcase_dir)[-1].strip("/")
            bug.sink.line = int(parts[1])
            bug.sink.col = int(parts[2])
            parts = bug_type.split(" ")
            bug.bug_type = parts[2].strip().strip(":")
            bug.description = self.flawfinder_rules[bug.bug_type]
            if bug.description.split("(")[-1].startswith("CWE"):
                bug.cwe_type = bug.description.split("(")[-1].strip().strip(")").replace(" ", "").replace(":", ",").split(",")
            bugs.append(bug)
        return bugs
