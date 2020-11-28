# -*- coding=utf-8 -*-
import os, sys, argparse, json
import juliet_parser as Juliet_parser
from xml.etree import ElementTree as ET
sys.path.append("..")
from bug import *
from glo import *


# 把原测试集加工成适合自动测评的样子
class BenchParser():
    def __init__(self):
        self.testsuite_name = ""

    # 从Juliet的文件名中提取测试样本名，如CWE114_Process_Control__w32_char_connect_socket_07.c 提取 CWE114_Process_Control__w32_char_connect_socket_07
    def __getTestcaseNameFromFilename(self, filename):
        part_2 = filename.split("_")[-1]
        if part_2.startswith("good") or part_2.startswith("bad"):
            part_2 = filename.split("_")[-2]
        num = part_2[0:2]
        signature = filename.split("_"+num)[0] + "_" + num
        return signature

    # 从Juliet的测试样本id里提取cwe编号和漏洞类型描述
    def __extractVulInfoFromTestcaseID(self, testcase_id):
        tmp = testcase_id.split("__")[0]
        cwe_type = tmp.split("_")[0]
        bug_type = ""
        for one in tmp.split("_")[1:]:
            bug_type = bug_type + one + " "
        bug_type = bug_type[:-1]
        return cwe_type, bug_type

    def __parseJulietManifest(self, f, cwe_list_filter=[]):
        bugs = []
        for event, elem in ET.iterparse(f, events=('end', 'end-ns')):
            if event == 'end' or event == 'end-ns':
                if elem.tag == 'file':
                    lst = []
                    for child in elem:
                        lst.append(child)
                    if len(lst) <= 0: # <file> doesn't have child <flaw>, skip
                        continue
                    fpath = elem.get('path')
                    # vul type is not in white list, skip
                    if len(cwe_list_filter) > 0 and fpath.split('_')[0] not in cwe_list_filter:
                        continue
                    # extract signature (which is used as testcase id) from file name
                    base = os.path.basename(fpath)
                    signature = self.__getTestcaseNameFromFilename(base)
                    for child in elem:
                        if child.tag == 'flaw':
                            bug = Bug()
                            bug.testcase_id = signature
                            bug.counterexample = 0
                            bug.bug_type = child.get('name').split(':')[0]
                            bug.sink.file = fpath
                            bug.sink.line = int(child.get('line'))
                            feature = Feature()
                            feature.name = "juliet_flow_variant_" + signature.split('_')[-1]
                            feature.description = "TBD"
                            feature.capability = "TBD"
                            bug.features.append(feature)
                            bugs.append(bug)
        return bugs

    # 从原测试集文件夹indir中，将一个个测试用例拷贝出来，放置在outdir里，testsuite_name目前支持'juliet', 'sard88', 'sard100', 'sard101'
    # 对于'juliet'测试集，cwe_list是白名单，仅拷贝其包含的CWE编号
    def copy(self, indir, outdir, testsuite_name='', cwe_list=[]):
        if not indir or not outdir:
            print("Error, neither indir nor outdir can be None")
            return
        bugs = []
        self.testsuite_name = testsuite_name
        indir = os.path.abspath(indir)
        outdir = os.path.abspath(outdir)
        if self.testsuite_name == 'juliet':
            for f in os.listdir(indir):
                if f.startswith('manifest') and f.endswith('.xml'):
                    f = os.path.join(indir, f)
                    bugs = self.__parseJulietManifest(f, cwe_list_filter=cwe_list)
            testcases = Juliet_parser.create_single_testcase(indir, outdir, cwe_list=cwe_list, preprocessed_bugs=bugs)
            return testcases

    def copyAndParse(self, indir, outdir, testsuite_name='', cwe_list=[]):
        bugs = []
        testcases = self.copy(indir, outdir, testsuite_name=testsuite_name, cwe_list=cwe_list)
        for testcase in testcases:
            bug = self.parse_one(testcase.testcase_id, testcase.testcase_dir_abs, testsuite_name)
            testcase.bugs = bug
        return testcases

    """
    def parse(self, testcase_paths, testsuite_name='juliet'):
        testcases, bugs = [], []
        for one in testcase_paths:
            one = one.strip()
            testcase = None
            if os.path.exists(os.path.join(one, Global.TESTCASE_METADATA)):
                with open(os.path.join(one, Global.TESTCASE_METADATA)) as fp:
                    content = fp.read()
                    testcase = Testcase.loads(content)
                    testcase.testcase_dir = os.path.abspath(one)
            else:
                testcase = Testcase()
                testcase.testcase_id = one.strip('/').split('/')[-1]
                testcase.testcase_dir = one
                testcase.testsuite_name = testsuite_name
                has_cpp, has_c = False, False
                for parent, dirnames, filenames in os.walk(one):
                    for f in filenames:
                        if f.endswith('cpp'):
                            has_cpp = True
                        if f.endswith('c'):
                            has_c = True
                if has_cpp:
                    testcase.compile_command = "g++ -DINCLUDEMAIN *.cpp -lpthread"
                    if has_c:
                        testcase.compile_command = "g++ -DINCLUDEMAIN *.cpp *.c -lpthread"
                elif has_c:
                    testcase.compile_command = "gcc -DINCLUDEMAIN *.c -lpthread"
            # 写入 testcase_metadata
            with open(os.path.join(one, Global.TESTCASE_METADATA), "w") as fp:
                fp.write(testcase.dumps())
            testcases.append(testcase)
            bugs.extend(self.parse_one(testcase.testcase_id, testcase.testcase_dir, testsuite_name))
        return testcases, bugs
    """

    def parse_one(self, testcase_id, testcase_dir_abs, testsuite_name):
        bugs = []
        if testsuite_name == 'juliet':
            for parent, dirnames, fnames in os.walk(testcase_dir_abs):
                for fname in fnames:
                    if fname.endswith("c") or fname.endswith("cpp") or fname.endswith("java"):
                        with open(os.path.join(parent,fname)) as fp:
                            lines = fp.readlines()
                            line_num = 1
                            for line in lines:
                                if line.find("##counterexample##") >= 0 or line.find("##bug##") >= 0:
                                    bug = Bug()
                                    bug.testcase_id = testcase_id
                                    cwe_type, bug.bug_type = self.__extractVulInfoFromTestcaseID(testcase_id)
                                    bug.cwe_type.append(cwe_type)
                                    bug.description = bug.bug_type
                                    bug.sink.file = os.path.join(parent,fname).split(testcase_dir_abs)[-1].strip("/") # 取相对路径
                                    bug.sink.line = line_num
                                    if line.find("##counterexample##") >= 0:
                                        bug.counterexample = 1
                                    else:
                                        bug.counterexample = 0
                                    bugs.append(bug)
                                line_num = line_num + 1
        return bugs

"""
    def parse_one(self, testcase_id, testcase_dir, testsuite_name):
        bugs = []
        bad_bug = None       # only one bad
        counterexamples = {} # may be several good, {"goodG2B":bug1, "goodB2G":bug2, ...}
        if testsuite_name == 'juliet':
            if os.path.exists(os.path.join(testcase_dir, Global.BUG_METADATA)):
                with open(os.path.join(testcase_dir, Global.BUG_METADATA)) as fp:
                    content = fp.read()
                    bad_bug = Bug.loads(content)
                    bad_bug.testcase_id = testcase_id
                    bad_bug.testcase_dir = testcase_dir
                    bad_bug.sink.file = os.path.join(testcase_dir, os.path.basename(bad_bug.sink.file))
                with open(os.path.join(testcase_dir, Global.BUG_METADATA), "w") as fp:
                    fp.write(bad_bug.dumps())
            infos = Juliet_parser.parse_juliet_vul_info(testcase_dir)
            for info in infos:
                sig = info['signature'] # bad, goodG2B, goodB2G, goodG2B1, goodG2B2, ...
                filename = info['filename']
                line = info['line']
                if sig.startswith("bad"):
                    if int(line) == bad_bug.sink.line and filename == bad_bug.sink.file:
                        continue   # 忽略解析出的与manifest.xml中相同的漏洞位置
                    other = Location()
                    other.file = filename
                    other.line = int(line)
                    bad_bug.other_suspicious.append(other)
                elif sig.startswith("good"):
                    if sig not in counterexamples.keys():
                        counterexamples[sig] = Bug()
                        counterexamples[sig].testcase_id = testcase_id
                        counterexamples[sig].testcase_dir = testcase_dir
                        counterexamples[sig].counterexample = 1
                        counterexamples[sig].sink.file = filename
                        counterexamples[sig].sink.line = int(line)
                    else:
                        other = Location()
                        other.file = filename
                        other.line = int(line)
                        counterexamples[sig].other_suspicious.append(other)
        for key in counterexamples.keys():
            bugs.append(counterexamples[key])
        bugs.append(bad_bug)
        return bugs
"""

if __name__ == "__main__":
    parser = BenchParser()
    testcases, bugs = parser.copyAndParse("/home/varas/Juliet_Test_Suite/C", "parsed_juliet", testsuite_name="juliet", cwe_list=["CWE476"])
