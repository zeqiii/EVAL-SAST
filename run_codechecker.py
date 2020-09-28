import os, sys
from impl import *
from glo import *
import subprocess
import codecs
from xml import etree
class Runner_codechecker(Runner):
    def __init__(self):
        Runner.__init__(self)
        self.name = "codechecker"

    def _genCMD(self, testcase_path, testsuite_name, output_path, output_file):
        if not os.path.exists(testcase_path):
            raise Exception(testcase_path+" does not exist")
        testcase_path = os.path.abspath(testcase_path)
        build_command = ""
        if testsuite_name == 'juliet':
            build_command = "\"cd %s && clang -DINCLUDEMAIN -lpthread *.c\""%(testcase_path)
        cmd = "CodeChecker check --ctu -b %s -o %s" %(build_command, output_path)
        print(cmd)
        return cmd

    def _parseOutput(self,testcase_path, testsuite_name, output_path, output_file):
        # 使用CodeChecker parse解析结果为json
        json_output_path = os.path.join(Config.TMP, "codechecker_output_json")
        if not os.path.exists(json_output_path):
            os.makedirs(json_output_path)
        cmd = "CodeChecker parse -e %s -o %s %s" %("json", json_output_path, output_path)
        print(cmd)
        os.system(cmd)
        report_json = os.path.join(json_output_path, "reports.json")
        return None

if __name__ == "__main__":
    csa = Runner_codechecker()
    testcase_path = sys.argv[1]
    testsuite_name = sys.argv[2]
    output_path = sys.argv[3]
    output_file = sys.argv[4]
    csa.start_one(testcase_path, testsuite_name, output_path, output_file)
