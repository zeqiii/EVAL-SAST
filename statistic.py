 import argparse

 class Statistic:
    def __init__(self):
        self.tool = ""

    # 统计结果
    def statistic(self, out_dir, task=-1):
        # 看看out_dir中是否有detected_bugs和detection_results的xml文件
        if task >= 0:
            detected_bugs_xml = os.path.join(out_dir, "detected_bugs_%s_task%d.xml"%(self.tool, task))
            detection_results_xml = os.path.join(out_dir, "detection_results_%s_task%d.xml"%(self.tool, task))
        else:
            detected_bugs_xml = os.path.join(out_dir, "detected_bugs_%s.xml"%(self.tool))
            detection_results_xml = os.path.join(out_dir, "detection_results_%s.xml"%(self.tool))
        if not os.path.exists(detected_bugs_xml) or not os.path.exists(detection_results_xml):
            raise Exception("detected_bugs or detection_results xml file not found")

        testcases = parse_manifest(detection_results_xml)
        detected_results = parse_manifest(detected_bugs_xml)

        # 输出基本型漏洞的检测结果
        for testcase in testcases:
            if testcase.testcase_type == "basic":
                for bug in testcase.bugs:
                    print(bug.testcase_id + " counterexample:%d"%(bug.counterexample) \
                        + " " + bug.detection_results[self.tool])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", metavar="TOOL", type=str, nargs=1, help='choose tools: codechecker|scan-build|flawfinder|cppcheck|rats|splint|uno')
    parser.add_argument('--input', '-i', help='Testsuite path. --input and --testsuite are mutually exclusive')
    parser.add_argument('--output', '-o', help='Output path, tool\'s output')
    parser.add_argument('--task', '-t', help='Specify a task id')

    args = parser.parse_args()

    stat = Statistic()
    stat.tool = args.tool[0]
    stat.statistic(args.input)