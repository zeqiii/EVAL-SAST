# -*- coding=utf-8 -*-
import os, threading, json, shutil, time, traceback, datetime

from glo import Config
from bug import *
from dao import *


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

    def start(self, testcases, out_dir, task=-1):
        detection_results = []
        dummy_testcases = [] # 存额外一份testcases，用来记录工具检测结果
        for testcase in testcases:
            one_out_dir = os.path.abspath(os.path.join(out_dir, testcase.testcase_id))
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
        if task >= 0:
            detected_bugs_xml = os.path.join(out_dir, "detected_bugs_%s_task%d.xml"%(self.tool, task))
            detection_results_xml = os.path.join(out_dir, "detection_results_%s_task%d.xml"%(self.tool, task))
        else:
            detected_bugs_xml = os.path.join(out_dir, "detected_bugs_%s.xml"%(self.tool))
            detection_results_xml = os.path.join(out_dir, "detection_results_%s.xml"%(self.tool))
        gen_manifest(dummy_testcases, detected_bugs_xml) # 生成记录工具输出的xml文件
        gen_manifest(testcases, detection_results_xml) # 生成记录工具检测结果的xml文件

    # 把测试结果上传到ceph和数据库中
    def upload_result(self, out_dir, task):
        # 看看out_dir中是否有detected_bugs和detection_results的xml文件
        if task >= 0:
            detected_bugs_xml = os.path.join(out_dir, "detected_bugs_%s_task%d.xml"%(self.tool, task))
            detection_results_xml = os.path.join(out_dir, "detection_results_%s_task%d.xml"%(self.tool, task))
        else:
            detected_bugs_xml = os.path.join(out_dir, "detected_bugs_%s.xml"%(self.tool))
            detection_results_xml = os.path.join(out_dir, "detection_results_%s.xml"%(self.tool))
        if not os.path.exists(detected_bugs_xml) or not os.path.exists(detection_results_xml):
            raise Exception("detected_bugs or detection_results xml file not found")

        db = DBUtil()
        db.connect()
        testcases = parse_manifest(detection_results_xml)
        detected_results = parse_manifest(detected_bugs_xml)
        # use ceph upload detected_bugs_xml
        os.system("python2 %s --c 0 --r %s --l %s" %(Config.ceph_du_py, detected_bugs_xml, detected_bugs_xml))

        sql = "select * from eval_detected_bugs where task_id=%d" %(task)
        db.cursor.execute(sql)
        result = db.cursor.fetchall()
        dt=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not result or len(result) <= 0:
            sql = "insert into eval_detected_bugs set task_id=%d, tool_name='%s', testsuite_name='%s', path_ceph='%s', date=str_to_date('%s', '%%Y-%%m-%%d %%H:%%i:%%S')" \
                %(task, pymysql.escape_string(self.tool), pymysql.escape_string(testcases[0].testsuite_name), \
                pymysql.escape_string(detected_bugs_xml), dt)
        else:
            sql = "update eval_detected_bugs set tool_name='%s', testsuite_name='%s', path_ceph='%s', date=str_to_date('%s', '%%Y-%%m-%%d %%H:%%i:%%S') where task_id=%d" \
                %(pymysql.escape_string(self.tool), pymysql.escape_string(testcases[0].testsuite_name), \
                pymysql.escape_string(detected_bugs_xml), dt, task)
        db.cursor.execute(sql)
        db.conn.commit()

        # 使用ceph上传整个检测结果
        index = out_dir.rstrip("/").rfind("/")
        root = ""
        sub_dir = out_dir.rstrip("/")
        if index > 0:
            root = out_dir[0:index]
            sub_dir = out_dir.rstrip("/")[index+1:]
        os.system("cd %s; zip -r %s.zip %s" %(root, sub_dir, sub_dir))
        os.system("python2 %s --c 0 --r %s --l %s" %(Config.ceph_du_py, sub_dir+".zip", os.path.join(root, sub_dir+".zip")))
        
        total_bugs = 0  # 工具报出的所有漏洞总和
        for one in detected_results:
            total_bugs = total_bugs + len(one.bugs)
        total_groundtruth_bugs, total_groundtruth_counterexamples, tp, tn, fp, fn = 0, 0, 0, 0, 0, 0
        for one in testcases:
            for bug in one.bugs:
                if bug.counterexample == 0:
                    total_groundtruth_bugs = total_groundtruth_bugs + 1
                elif bug.counterexample == 1:
                    total_groundtruth_counterexamples = total_groundtruth_counterexamples + 1
                r = bug.detection_results[self.tool]
                if r == "TP":
                    tp = tp + 1
                elif r == "FP":
                    fp = fp + 1
                elif r == "FN":
                    fn = fn + 1
                elif r == "TN":
                    tn = tn + 1

        # 上传结果数据
        sql = "select * from eval_result where task=%d" %(task)
        db.cursor.execute(sql)
        result = db.cursor.fetchall()
        dt=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not result or len(result) <= 0:
            sql = "insert into eval_result set task=%d, detected_vul_total=%d, missing_rate=%f, false_rate=%f, \
                result_url='%s', marked_true_toal=%d, marked_false_toal=%d, tp_num=%d, fp_num=%d, tn_num=%d, fn_num=%d, \
                end_time=str_to_date('%s', '%%Y-%%m-%%d %%H:%%i:%%S')" \
                %(task, total_bugs, 1.0*fn/total_groundtruth_bugs, 1.0*fp/total_groundtruth_counterexamples, sub_dir+".zip", \
                total_groundtruth_bugs, total_groundtruth_counterexamples, tp, fp, tn, fn, dt)
        else:
            sql = "update eval_result set detected_vul_total=%d, missing_rate=%f, false_rate=%f, \
                result_url='%s', marked_true_toal=%d, marked_false_toal=%d, tp_num=%d, fp_num=%d, tn_num=%d, fn_num=%d, \
                end_time=str_to_date('%s', '%%Y-%%m-%%d %%H:%%i:%%S') where task=%d" \
                %(total_bugs, 1.0*fn/total_groundtruth_bugs, 1.0*fp/total_groundtruth_counterexamples, sub_dir+".zip", \
                total_groundtruth_bugs, total_groundtruth_counterexamples, tp, fp, tn, fn, dt, task)
        db.cursor.execute(sql)
        db.conn.commit()
        db.disconnect()


    # clean result
    def __clean(self):
        print("cleaning...")
        shutil.rmtree(Config.TMP)
        os.makedirs(Config.TMP)

    # generate cmd based on testcase_path and output_path, in order to call tools
    # please rewrite this method
    def _genCMD(self, testcase, output_path, output_file="result.out"):
        return ""

    # parse output data, return a list of Bug objects
    # please rewrite this method
    def _parseOutput(self, testcase, output_path, output_file="result.out"):
        return None
