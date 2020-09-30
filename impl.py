# -*- coding=utf-8 -*-
import os, threading, json, shutil, time, traceback
from glo import Config
from bug import *


def get_testcase_path(testcase_id, testsuite_home_dir=Config.TESTSUITE):
    for parent, dirs, files in os.walk(testsuite_home_dir):
        parent = os.path.abspath(parent)
        for d in dirs:
            if d == testcase_id and parent.find(os.path.abspath(Config.OUTPUT)) < 0:
                return os.path.abspath(os.path.join(parent, d))
    return None


class Runner:

    # 1，从数据库查询testcase                       # 1，运行工具输出结果
    # 2，根据testcase id定位testcase path           # 2，分析结果
    # 3，调用工具输出结果                           # 3，更新数据库
    # 4，分析结果
    # 5，更新数据库

    # GLOBAL VARIANTS
    lock = threading.Lock()           # for thread safe operation

    def __init__(self):
        self.tool = ""                # tested tool's name
        self.testcases = {}           # set of testcase, {testcase_name:testcase_path}
        self.tooloutputs = {}         # set of tool's output, {testcase_name:output_file}
        self.has_tested = False       # flag to see if testing has been finished
        self.has_parsed = False       # flag to see if parsing has been finished
        if not os.path.exists(Config.TMP):
            os.makedirs(Config.TMP)
        if not os.path.exists(Config.OUTPUT):
            os.makedirs(Config.OUTPUT)

    def judge(self, real_bug, bugs):
        # see if there exists one bug match the real bug
        for bug in bugs:
            if real_bug.equal(bug):
                if real_bug.is_vul == 1:
                    return "TP", bug
                elif real_bug.is_vul == 0:
                    return "FP", bug
        if real_bug.is_vul == 0:
            return "TN", None
        else:
            return "FN", None

    def start_one(self, testcase, one_output_path):
        cmd = self._genCMD(testcase, one_output_path)
        print("+++++++++++++++++++++++++")
        print(cmd)
        print("+++++++++++++++++++++++++")
        os.system(cmd)
        bugs = self._parseOutput(testcase, one_output_path)
        return bugs

    def start(self, testcases, output_path):
        for testcase in testcases:
            testcase_path = testcase.testcase_dir
            testsuite_name = testcase.testsuite_name
            testcase_id = testcase.testcase_id
            one_output_path = os.path.join(output_path, testcase_id)
            output_file = testcase_id
            bugs = self.start_one(testcase, one_output_path)
            

    # clean result
    def __clean(self):
        print("cleaning...")
        shutil.rmtree(Config.OUTPUT)
        os.makedirs(Config.OUTPUT)
        shutil.rmtree(Config.TMP)
        os.makedirs(Config.TMP)
        files = os.listdir(Config.HOME)
        for f in files:
            if f.endswith(".o") or f.endswith(".class"):
                os.remove(os.path.join(Config.HOME, f))

    # generate cmd based on testcase_path and output_path, in order to call tools
    # please rewrite this method
    def _genCMD(self, testcase, output_path, output_file="result.out"):
        return ""

    # select vuls from DB
    # please rewrite this method
    def _select_from_DB(self, num):
        pass

    # parse output data, return a list of Bug objects
    # please rewrite this method
    def _parseOutput(self, testcase, output_path, output_file="result.out"):
        return None

    # update DB
    # please rewrite this method
    def _update(self, _id, result, details=[]):
        pass
