# -*- coding=utf-8 -*-
import argparse, json, os
from benchmark_parser import BenchParser
from bug import *
from run_codechecker import Runner_codechecker


def display(bugs):
    for bug in bugs:
        print("=====================")
        print("testcase_id: " + bug.testcase_id)
        print("testcase_dir: " + bug.testcase_dir)
        print("description: " + bug.description)
        print("sink: " + bug.sink.toString())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", metavar="ACTTION[parse|parseone|copy|copyandparse|readjson|sca|compare]", type=str, nargs=1, help='choose action')
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
    else:
        cwelist = []

    bp = BenchParser()

    testcases, bugs, detection_results = [], [], []
    if args.action[0] == "copy":
        testcases = bp.copy(in_dirs[0], out_dir, testsuite_name=testsuite_name, cwe_list=cwelist)
        info = {}
        for testcase in testcases:
            info[testcase] = testcase.dumps()
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
    if args.action[0] == "readjson" or args.action[0] == "sca" or args.action[0] == "compare":
        # --input testcases.json bugs.json
        for in_dir in in_dirs:
            with open(in_dir) as fp:
                jsonstr = fp.read()
                obj = json.loads(jsonstr)
                if in_dir.endswith(".json") and ((in_dir.startswith("bugs") or os.path.splitext(in_dir)[0].endswith("bugs")) or \
                   (in_dir.startswith("compare_results") or os.path.splitext(in_dir)[0].endswith("compare_results"))):
                    print("bugs.json")
                    for one in obj:
                        one_bug = Bug.loads(one)
                        bugs.append(one_bug)
                elif in_dir.endswith(".json") and (in_dir.startswith("testcases") or os.path.splitext(in_dir)[0].endswith("testcases")):
                    print("testcases.json")
                    for one in obj.keys():
                        testcase = Testcase.loads(obj[one])
                        testcases.append(testcase)
                elif in_dir.endswith(".json") and (in_dir.startswith("detection_results") or os.path.splitext(in_dir)[0].endswith("detection_results")):
                    print("detection_results.json")
                    for one in obj.keys():
                        for bug_str in obj[one]:
                            detection_results.append(Bug.loads(bug_str))
    targets, ground_truths = testcases, bugs
    runner = None
    if args.action[0] == "sca":
        if args.tool == "codechecker":
            runner = Runner_codechecker()
            detection_results = runner.start(testcases, out_dir)
    if args.action[0] == "compare":
        for ground_truth in ground_truths:
            for detection_result in detection_results:
                rt = ground_truth.compare(detection_result, args.tool)
                if rt:
                    print(ground_truth.dumps())
                    break
        compare_info = []
        for truth in ground_truths:
            compare_info.append(truth.dumps())
        with open("compare_results.json", "w") as fp:
            fp.write(json.dumps(compare_info))

    tp, fp, fn, tn = 0, 0, 0, 0
    tps, fps = [], []
    print(len(ground_truths))
    for one in ground_truths:
        if args.tool in one.detection_results.keys():
            if one.detection_results[args.tool] == "TP":
                tp = tp + 1
                tps.append(one)
            if one.detection_results[args.tool] == "FP":
                fp = fp + 1
                fps.append(one)
        else:
            if one.counterexample == 0:
                fn = fn + 1
            else:
                tn = tn + 1
    print("%d, %d, %d, %d" %(tp, fp, tn, fn))
    print(len(detection_results))
    #display(tps)
    #display(fps)
