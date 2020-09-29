import os, sys
from impl import *
from glo import *
from bug import *
class Runner_codechecker(Runner):
    def __init__(self):
        Runner.__init__(self)
        self.name = "codechecker"

    def _genCMD(self, testcase, output_path, output_file="result.out"):
        if not os.path.exists(testcase.testcase_dir):
            raise Exception(testcase.testcase_dir+" does not exist")
        build_command = ""
        if testcase.testsuite_name == 'juliet':
            build_command = "\"cd %s && %s\""%(testcase.testcase_dir, testcase.compile_command)
        cmd = "CodeChecker check --ctu -b %s -d clang-diagnostic-unused-parameter -o %s" %(build_command, output_path)
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
                print("============================")
                print(bug_result["check_name"])
                print(bug_result["description"])
                print(bug_result["category"])
                print(bug_result["type"])
                print(bug_result["location"])
                print(bug_result["files"])
                print(bug_result["path"])
                bug = Bug()
                bug.testcase_id = testcase.testcase_id
                bug.testcase_dir = testcase.testcase_dir
                bug.sink.line = bug_result["location"]["line"]
                findex = bug_result["location"]["file"]
                bug.sink.file = bug_result["files"][findex]
                bugs.append(bug)
        os.system("rm -rf %s" %(output_path))
        os.system("mv %s %s" %(json_output_path, output_path))
        return bugs

if __name__ == "__main__":
    csa = Runner_codechecker()
    testcase_path = sys.argv[1]
    testsuite_name = sys.argv[2]
    output_path = sys.argv[3]
    output_file = sys.argv[4]
    csa.start_one(testcase_path, testsuite_name, output_path, output_file)
