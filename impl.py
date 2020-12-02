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

    # 看看real_bug有没有被检测到
    def judge(self, ground_truth, detected_bugs):
        # see if there exists one bug match the real bug
        for bug in detected_bugs:
            if ground_truth.is_loc_same(bug): # 两个bug的位置一致
                if bug_type_compare(ground_truth, bug): # 两个bug的类型一致
                    if ground_truth.counterexample == 0:
                        return "TP"
                    elif ground_truth.counterexample == 1:
                        return "FP"
        if ground_truth.counterexample == 1:
            return "TN"
        else:
            return "FN"

    def start_one(self, testcase, one_out_dir):
        cmd = self._genCMD(testcase, one_out_dir)
        os.system(cmd)
        bugs = self._parseOutput(testcase, one_out_dir)
        return bugs

    def start(self, testcases, out_dir):
        detection_results = []
        dummy_testcases = [] # 存额外一份testcases，用来记录工具检测结果
        for testcase in testcases:
            one_out_dir = os.path.abspath(os.path.join(out_dir, testcase.testcase_id))
            print(one_out_dir)
            if os.path.exists(one_out_dir): # 若已经执行过漏洞检测，则直接解析输出即可
                detected_bugs = self._parseOutput(testcase, one_out_dir)
            else: # 否则执行漏洞检测
                detected_bugs = self.start_one(testcase, one_out_dir)
            for ground_truth in testcase.bugs:
                judge_result = self.judge(ground_truth, detected_bugs)
                ground_truth.detection_results[self.tool] = judge_result # 存储检测结果
            dummy_testcase = testcase.copy()
            dummy_testcase.bugs = detected_bugs
            dummy_testcases.append(dummy_testcase)
        detected_bugs_xml = os.path.join(out_dir, "detected_bugs_%s.xml"%(self.tool))
        detection_results_xml = os.path.join(out_dir, "detection_results_%s.xml"%(self.tool))
        gen_manifest(dummy_testcases, detected_bugs_xml) # 生成记录工具输出的xml文件
        gen_manifest(testcases, detection_results_xml) # 生成记录工具检测结果的xml文件

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

    # parse output data, return a list of Bug objects
    # please rewrite this method
    def _parseOutput(self, testcase, output_path, output_file="result.out"):
        return None
