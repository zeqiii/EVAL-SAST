import argparse, os
from bug import *

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass
    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass 
    return False

# 从Juliet的文件名中提取测试样本名，如CWE114_Process_Control__w32_char_connect_socket_07.c 提取 CWE114_Process_Control__w32_char_connect_socket
# signature可以看作是目标程序的种类
def getSignature(filename):
    part_2 = filename.split("_")[-1]
    if part_2.startswith("good") or part_2.startswith("bad"):
        part_2 = filename.split("_")[-2]
    num = ""
    for index in range(0, len(part_2)):
        if is_number(part_2[index]):
            num = num + part_2[index]
        else:
            break
    signature = filename.split("_"+num)[0]
    return signature

class Statistic:
    def __init__(self):
        self.tool = ""
        self.testcases = None
        self.detected_results = None

    def initData(self, out_dir, tool="", task=-1):
        self.tool = tool
        # 看看out_dir中是否有detected_bugs和detection_results的xml文件
        if task >= 0:
            detected_bugs_xml = os.path.join(out_dir, "detected_bugs_%s_task%d.xml"%(self.tool, task))
            detection_results_xml = os.path.join(out_dir, "detection_results_%s_task%d.xml"%(self.tool, task))
        else:
            detected_bugs_xml = os.path.join(out_dir, "detected_bugs_%s.xml"%(self.tool))
            detection_results_xml = os.path.join(out_dir, "detection_results_%s.xml"%(self.tool))
        if not os.path.exists(detected_bugs_xml) or not os.path.exists(detection_results_xml):
            raise Exception("detected_bugs or detection_results xml file not found")

        self.testcases = sorted(parse_manifest(detection_results_xml))
        self.detected_results = parse_manifest(detected_bugs_xml)

    # 统计结果
    def statistic_basic(self):
        # 输出基本型漏洞的检测结果
        for testcase in self.testcases:
            if testcase.testcase_type == "basic":
                for bug in testcase.bugs:
                    print(bug.testcase_id + " counterexample:%d"%(bug.counterexample) \
                        + " " + bug.detection_results[self.tool])
    def statistic_filter(self, keyword):
        # 输出基本型漏洞的检测结果
        for testcase in self.testcases:
            if testcase.testsuite_name.startswith("juliet"):
                sig = getSignature(testcase.testcase_id)
                if sig == keyword:
                    for bug in testcase.bugs:
                        print(bug.testcase_id + " counterexample:%d"%(bug.counterexample) \
                            + " " + bug.detection_results[self.tool])



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", metavar="TOOL", type=str, nargs=1, help='choose action: basic|filter')
    parser.add_argument('--tool', help='tool name')
    parser.add_argument('--input', '-i', help='Testsuite path. --input and --testsuite are mutually exclusive')
    parser.add_argument('--output', '-o', help='Output path, tool\'s output')
    parser.add_argument('--task', '-t', help='Specify a task id')
    parser.add_argument('--keyword', '-k', help='filter out keyword')

    args = parser.parse_args()

    stat = Statistic()
    stat.initData(args.input, tool=args.tool)
    if args.action[0] == 'basic':
        stat.statistic_basic(args.input)
    elif args.action[0] == 'filter':
        stat.statistic_filter(args.keyword)
