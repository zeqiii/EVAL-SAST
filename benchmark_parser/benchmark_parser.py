# -*- coding=utf-8 -*-
import os, sys, argparse, json
import juliet_parser as Juliet_parser
import xml.dom.minidom as minidom
from xml.etree import ElementTree as ET
sys.path.append("..")
from bug import *
from glo import *


# 把原测试集加工成适合自动测评的样子
class BenchParser():
    def __init__(self):
        self.testsuite_name = ""

    def __is_number(s):
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

    # 从Juliet的文件名中提取测试样本名，如CWE114_Process_Control__w32_char_connect_socket_07.c 提取 CWE114_Process_Control__w32_char_connect_socket_07
    def __getTestcaseNameFromFilename(self, filename):
        part_2 = filename.split("_")[-1]
        if part_2.startswith("good") or part_2.startswith("bad"):
            part_2 = filename.split("_")[-2]
        num = ""
        for index in range(0, len(part_2)):
            if self.__is_number(part_2[index]):
                num = num + part_2[index]
            else:
                break
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
            testcase.bugs = self.parse_one(testcase.testcase_id, testcase.testcase_dir_abs, testsuite_name)
        return testcases

    def parse(self, testsuite_dir, testsuite_name):
        manifest = os.path.join(testsuite_dir, "manifest.xml")
        testcases = parse_manifest(manifest)
        # 重新解析一遍漏洞
        for testcase in testcases:
            testcase.testcase_dir_abs = os.path.abspath(os.path.join(testsuite_dir, testcase.testcase_dir))
            testcase.bugs = self.parse_one(testcase.testcase_id, testcase.testcase_dir_abs, testsuite_name)
        return testcases

    def parse_one(self, testcase_id, testcase_dir_abs, testsuite_name):
        bugs = []
        if testsuite_name == 'juliet':
            for parent, dirnames, fnames in os.walk(testcase_dir_abs):
                for fname in fnames:
                    if fname.endswith("c") or fname.endswith("cpp") or fname.endswith("java"):
                        with open(os.path.join(parent,fname)) as fp:
                            func_info = None
                            lines = fp.readlines()
                            line_num = 1
                            for line in lines:
                                if line.find("##counterexample##") >= 0 or line.find("##bug##") >= 0:
                                    if not func_info:
                                        func_info = Juliet_parser.gen_func_info(os.path.join(parent,fname))
                                        func_info = Juliet_parser.parse_func_info(func_info)
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
                                    # 解析bug feature
                                    feature = Feature()
                                    feature.name = "juliet_flow_variant__" + testcase_id.split('_')[-1]
                                    for key1 in func_info.keys():
                                        if key1.find(fname) < 0:
                                            continue
                                        for key2 in func_info[key1].keys(): # key2是函数名
                                            startline = func_info[key1][key2]['funcstartline']
                                            endline = func_info[key1][key2]['funcendline']
                                            if bug.sink.line >= int(startline) and bug.sink.line <= int(endline):
                                                part = key2.split('_')[-1]
                                                if not part.startswith('good') and not part.startswith('bad'):
                                                    part = key2.split('_')[-2]
                                                feature.name = feature.name + "_" + part
                                    bug.features.append(feature)
                                    bugs.append(bug)
                                line_num = line_num + 1
        return bugs




if __name__ == "__main__":
    parser = BenchParser()
    testcases = parser.copyAndParse("/home/varas/Juliet_Test_Suite/C", "parsed_juliet", testsuite_name="juliet", cwe_list=["CWE476"])
    for testcase in testcases:
        testcase.toXml()
    dom = minidom.Document()
    testsuite_node = dom.createElement("testsuite")
    testsuite_node.setAttribute('name', 'juliet')
    for testcase in testcases:
        testsuite_node.appendChild(testcase.domobj)
    dom.appendChild(testsuite_node)
    with open("manifest.xml", "w") as fp:
        dom.writexml(fp, indent="", addindent="    ", newl="\n", encoding="UTF-8") 
