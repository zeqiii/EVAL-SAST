# -*- coding=utf-8 -*-
import argparse, json
from benchmark_parser import BenchParser
from bug import *
from run_codechecker import Runner_codechecker

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", metavar="ACTTION[parse|parseone|copy|copyandparse|readjson|sca]", type=str, nargs=1, help='choose action')
    parser.add_argument('--input', '-i', nargs='+', help='Input path, copy source path')
    parser.add_argument('--output', '-o', help='Output path, copy destination path')
    parser.add_argument('--benchmark', '-b', help='Name of input benchmark, which could be: "juliet"')
    parser.add_argument('--cwelist', '-l', help='White list of CWE IDs, use space to seprate them, e.g., -l "CWE121 CWE120"')
    parser.add_argument('--testcase_id', '-id', help='ID of testcase, needed when performing "parseone"')
    parser.add_argument('--tool', '-t', help='Name of the evaluated tool. Needed when action is sca')

    args = parser.parse_args()
    in_dirs = args.input
    out_dir = args.output
    testsuite_name = args.benchmark
    cwelist = args.cwelist
    if cwelist:
        cwelist = cwelist.split(' ')
    bp = BenchParser()

    testcases, bugs = [], []
    if args.action[0] == "copy":
        testcases = bp.copy(in_dirs[0], out_dir, testsuite_name=testsuite_name, cwe_list=cwelist)
        info = {}
        for testcase in testcases:
            info[testcase] = tescase.dumps()
        info_str = json.dumps(info)
        with open("testcases.json", "w") as fp:
            fp.write(info_str)
    if args.action[0] == "copyandparse":
        testcases, bugs = bp.copyAndParse(in_dirs[0], out_dir, testsuite_name=testsuite_name, cwe_list=cwelist)
        info = {}
        bug_info = []
        for testcase in testcases:
            info[testcase.testcase_id] = testcase.dumps()
        info_str = json.dumps(info)
        with open("testcases.json", "w") as fp:
            fp.write(info_str)
        for bug in bugs:
            bug_info.append(bug.dumps())
        with open("bugs.json", "w") as fp:
            fp.write(json.dumps(bug_info))
    if args.action[0] == "parseone":
        testcase_id = args.testcase_id
        bug = bp.parse_one(testcase_id, in_dirs[0], testsuite_name)
        print(bug.dumps())
    if args.action[0] == "parse":
        if not os.path.isdir(in_dirs[0]):  # 这是一个文件，里面是测试样本路径列表
            with open(in_dirs[0]) as fp:
                paths = fp.readlines()
                testcases, bugs = bp.parse(paths, testsuite_name=testsuite_name)
        else:
            testcases, bugs = bp.parse(in_dirs, testsuite_name=testsuite_name)
    if args.action[0] == "readjson" or args.action[0] == "sca":
        # --input testcases.json bugs.json
        for in_dir in in_dirs:
            with open(in_dir) as fp:
                jsonstr = fp.read()
                obj = json.loads(jsonstr)
                if type(obj) == type([]):
                    for one in obj:
                        one_bug = Bug.loads(one)
                        bugs.append(one_bug)
                elif type(obj) == type({}):
                    for one in obj.keys():
                        testcase = Testcase.loads(obj[one])
                        testcases.append(testcase)
    
    targets, ground_truths = testcases, bugs
    if args.action[0] == "sca":
        tool = args.tool
        if tool == "codechecker":
            runner = Runner_codechecker()
            runner.start(testcases, out_dir)
            runner.compare(out_dir, ground_truths)
    print(len(targets))
    print(len(ground_truths))