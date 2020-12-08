# -*- coding=utf-8 -*-
import argparse, json, os
from bug import *
from run_codechecker import Runner_codechecker
from run_scanbuild import Runner_scanbuild
from run_flawfinder import Runner_flawfinder
from run_cppcheck import Runner_cppcheck
from run_rats import Runner_rats
from run_splint import Runner_splint
from run_uno import Runner_uno


def display(bugs):
    for bug in bugs:
        print("=====================")
        print("testcase_id: " + bug.testcase_id)
        print("testcase_dir: " + bug.testcase_dir)
        print("description: " + bug.description)
        print("sink: " + bug.sink.toString())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", metavar="TOOL", type=str, nargs=1, help='choose tools: codechecker|scan-build|flawfinder|cppcheck|rats')
    parser.add_argument('--input', '-i', help='Testsuite path')
    parser.add_argument('--output', '-o', help='Output path, tool\'s output')

    args = parser.parse_args()
    testsuite_path = args.input
    manifest_file = os.path.join(testsuite_path, "manifest.xml")
    out_dir = args.output
    testcases = parse_manifest(manifest_file)
    for testcase in testcases:
        testcase.testcase_dir_abs = os.path.abspath(os.path.join(testsuite_path, testcase.testcase_dir))
    testsuite_name = testcases[0].testsuite_name

    # 初始化检测工具接口
    runner = None # 检测工具接口runner
    if args.tool[0] == "codechecker":
        # 调用codechecker来执行检测
        runner = Runner_codechecker()
    if args.tool[0] == "scan-build":
        # 调用scan-build来执行检测
        runner = Runner_scanbuild()
    if args.tool[0] == "flawfinder":
        # 调用flawfinder来执行检测
        runner = Runner_flawfinder()
    if args.tool[0] == "cppcheck":
        # 调用cppcheck来执行检测
        runner = Runner_cppcheck()
    if args.tool[0] == "rats":
        # 调用rats来执行检测
        runner = Runner_rats()
    if args.tool[0] == "splint":
        # 调用splint来执行检测
        runner = Runner_splint()
    if args.tool[0] == "uno":
        # 调用uno来执行检测
        runner = Runner_uno()
    # 执行检测
    runner.start(testcases, out_dir)



"""
    testcases, bugs, detection_results = [], [], []

    targets, ground_truths = testcases, bugs
    runner = None
    if args.action[0] == "sca":
        if args.tool == "codechecker":
            runner = Runner_codechecker()
            detection_results = runner.start(testcases, out_dir)
        if args.tool == "scan-build":
            runner = Runner_scanbuild()
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
"""
