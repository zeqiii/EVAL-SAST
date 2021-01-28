# -*- coding=utf-8 -*-
import os, sys, argparse, json
import juliet_parser as Juliet_parser
import xml.dom.minidom as minidom
import juliet_marker
from xml.etree import ElementTree as ET
sys.path.append("..")
from bug import *
from glo import *
from dao import *

# {signature:([source_feature1, source_feature2, ...], sink)}
keywords = {}

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

# 把原测试集加工成适合自动测评的样子
class BenchParser():
    def __init__(self):
        self.testsuite_name = ""

    # 从Juliet的文件名中提取测试样本名，如CWE114_Process_Control__w32_char_connect_socket_07.c 提取 CWE114_Process_Control__w32_char_connect_socket_07
    def __getTestcaseNameFromFilename(self, filename):
        part_2 = filename.split("_")[-1]
        if part_2.startswith("good") or part_2.startswith("bad"):
            part_2 = filename.split("_")[-2]
        num = ""
        for index in range(0, len(part_2)):
            if is_number(part_2[index]):
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
        if self.testsuite_name.startswith('juliet'):
            for f in os.listdir(indir):
                if f.startswith('manifest') and f.endswith('.xml'):
                    f = os.path.join(indir, f)
                    bugs = self.__parseJulietManifest(f, cwe_list_filter=cwe_list)
            testcases = Juliet_parser.create_single_testcase(indir, outdir, cwe_list=cwe_list, preprocessed_bugs=bugs)
            for testcase in testcases:
                testcase.testsuite_name = testsuite_name
            return testcases

    # 拷贝原有测试集，并按照我们定义的测试集结构重新组织，然后解析原有测试集中的标注信息，构造新测试集的manifest文件
    def copyAndParse(self, indir, outdir, testsuite_name='', cwe_list=[]):
        bugs = []
        testcases = self.copy(indir, outdir, testsuite_name=testsuite_name, cwe_list=cwe_list)
        for testcase in testcases:
            testcase.bugs = self.parse_one(testcase.testcase_id, testcase.testcase_dir_abs, testsuite_name)
        return testcases

    # 再解析一遍测试集，更新测试集的标注
    def parse(self, testsuite_dir, testsuite_name):
        manifest = os.path.join(testsuite_dir, "manifest.xml")
        testcases = parse_manifest(manifest)
        # 重新解析一遍漏洞
        for testcase in testcases:
            testcase.testcase_dir_abs = os.path.abspath(os.path.join(testsuite_dir, testcase.testcase_dir))
            testcase.bugs = self.parse_one(testcase.testcase_id, testcase.testcase_dir_abs, testsuite_name)
        return testcases

    # 对一个测试集进行解析
    def parse_one(self, testcase_id, testcase_dir_abs, testsuite_name):
        bugs = []
        if testsuite_name.startswith('juliet'):
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
                                                    part = key2.split(':')[-1]
                                                    if len(key2.split('_')) >= 2:
                                                        part = key2.split('_')[-2]
                                                feature.name = feature.name + "_" + part
                                    bug.features.append(feature)
                                    # 解析bug_newtype
                                    signature = juliet_marker.getSignature(bug.testcase_id)
                                    if signature in keywords.keys():
                                        bug.bug_newtype["source"] = keywords[signature]["source"]
                                        bug.bug_newtype["sink"] = keywords[signature]["sink"]
                                        bug.bug_newtype["cwe"] = cwe_type
                                    bugs.append(bug)
                                line_num = line_num + 1
        elif testsuite_name.startswith("sard"):
            pass # TBD

        return bugs




if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", metavar="ACTION", type=str, nargs=1, help='choose action: parse|refresh|upload')
    parser.add_argument('--input', '-i', help="path of the original test suite | path of the manifest file")
    #parser.add_argument('--output', '-o', help="output path of the parsed testsuite")
    parser.add_argument('--name', '-n', help="name of the test suite")
    parser.add_argument('--cwe', '-c', help="cwe list, split with ',' e.g. -c \"CWE121,CWE122\"")
    parser.add_argument('--type', '-t', help="type of testsuite, 0 synthetic, 1 real-world")
    parser.add_argument('--keywords', '-k', help="针对juliet测试集，填入keywords文件路径，文件中包含目标程序的signature、source和counterexample_sink")

    args = parser.parse_args()

    # 初始化keywords
    if args.keywords:
        keywords = juliet_marker.parse_keywords(args.keywords)

    _input = args.input
    _type = 0
    _cwe = []
    if args.cwe:
        _cwe = args.cwe.split(",")
        for i in range(0, len(_cwe)):
            _cwe[i] = _cwe[i].strip()
    if args.type:
        _type = int(args.type)
        print(_type)
        if _type != 0 and _type != 1:
            print("--type can only be 0 or 1")
            exit(1)

    db = DBUtil()
    db.connect()
    if args.action[0] == "parse" or args.action[0] == "refresh":
        parser = BenchParser()
        #cwe_list = ["CWE121","CWE122","CWE123","CWE124","CWE126","CWE127","CWE134","CWE190","CWE369","CWE415","CWE416","CWE457","CWE476"]
        # 用测试集的名称作为输出文件夹的名称
        testcases = []
        if args.action[0] == "parse":
            testcases = parser.copyAndParse(args.input, args.name, testsuite_name=args.name, cwe_list=_cwe)
        elif args.action[0] == "refresh":
            testcases = parser.parse(args.input, args.name)
        gen_manifest(testcases, os.path.join(args.name, "manifest.xml"))
        # 压缩
        os.system("zip -r %s.zip %s" %(args.name, args.name))
        # 上传
        os.system("python2 %s --c %d --r %s --l %s" %(Config.ceph_du_py, 0, args.name+".zip", args.name+".zip"))
        # 更新数据表eval_testsuite
        db.update_testsuite(name=args.name, download_url=args.name+".zip", type=_type)
    if args.action[0] == "upload":
        testcases = parse_manifest(_input)
        db.insert_testcase(testcases)
        db.insert_groundtruth_bug(testcases)
    db.disconnect()
