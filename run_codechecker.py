# -*- coding=utf-8 -*-
import os, sys
from impl import *
from glo import *
from bug import *

def outputReader(output_file):
    results = None
    with open(output_file) as fp:
        results = json.loads(fp.read())
    if not results:
        return None
    for result in results:
        print("=======================================================================")
        print("check_name: %s" %(result["check_name"]))
        print("type: %s" %(result["type"]))
        print("description: %s" %(result["description"]))
        file_index = result["location"]["file"]
        line_num = result["location"]["line"]
        col_num = result["location"]["col"]
        print("location: %s:line%d:col%d" %(result["files"][file_index], line_num, col_num))
        print("=======================================================================")


class Runner_codechecker(Runner):
    def __init__(self):
        Runner.__init__(self)
        self.name = "codechecker"

    def _genCMD(self, testcase, output_path, output_file="result.out"):
        if not os.path.exists(testcase.testcase_dir_abs):
            raise Exception(testcase.testcase_dir_abs + " does not exist")
        build_command = ""
        # 根据不同的测试集，实现不同的编译方法
        if testcase.testsuite_name == 'juliet':
            build_command = "\"cd %s && %s\""%(testcase.testcase_dir_abs, testcase.compile_command)
        cmd = "CodeChecker check --ctu -b %s -o %s" %(build_command, output_path)
        return cmd

    def _parseOutput(self, testcase, output_path, output_file="result.out"):
        # 使用CodeChecker parse解析结果为json
        json_output_path = os.path.join(Config.TMP, "%s"%(testcase.testcase_id))
        if not os.path.exists(json_output_path):
            os.makedirs(json_output_path)
        cmd = "CodeChecker parse -e %s -o %s %s" %("json", json_output_path, output_path)
        os.system(cmd)
        report_json = os.path.join(json_output_path, "reports.json")
        bugs = []
        with open(report_json) as fp:
            bug_results = json.loads(fp.read())
            for bug_result in bug_results:
                bug = Bug()
                bug.testcase_id = testcase.testcase_id
                bug.description = bug_result["check_name"] + " " +  bug_result["description"]
                bug.bug_type = bug_result["type"]
                bug.sink.line = bug_result["location"]["line"]
                findex = bug_result["location"]["file"]
                bug.sink.file = bug_result["files"][findex]
                bugs.append(bug)
        os.system("mv %s %s" %(report_json, output_path))
        os.system("rm -rf %s" %(json_output_path))
        return bugs

if __name__ == "__main__":
    json_file = sys.argv[1]
    outputReader(json_file)