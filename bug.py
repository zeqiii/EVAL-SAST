# -*- coding=utf-8 -*-
import json
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from nltk.stem import WordNetLemmatizer
from glo import *
from CWE import *

class Feature():
    def __init__(self):
        self.name = ""  # 语法特征名称
        self.description = "" # 描述
        self.capability = "" # 处理该语法特征所需能力

    def copy(self):
        feat = Feature()
        feat.name = self.name
        feat.description = self.description
        feat.capability = self.capability
        return feat

class Location():
    def __init__(self):
        self.file = ""
        self.line = -1
        self.col = -1

    def toString(self):
        s = ""
        s = self.file + ":" + str(self.line) + ":" + str(self.col)
        return s

    def copy(self):
        loc = Location()
        loc.file = self.file
        loc.line = self.line
        loc.col = self.col
        return loc

class Bug():
    def __init__(self):
        self.testcase_id = ""
        self.counterexample = 0
        self.bug_type = ""       # deprecated, string format of bug info
        self.severity = ""       # severity: info, low, medium, high, critical
        self.description = ""
        self.cwe_type = []       # example: [CWE-193, CWE-122]
        self.source = Location()
        self.sink = Location()
        self.other_suspicious = []
        self.execution_path = [] # 执行路径，Location列表，掐去source和sink
        self.features = [] # Feature列表
        self.poc = ""
        self.detection_results = {} # example: {"tool_name":"TP"}

    # 对比本身与参数bug是否在同一位置
    # 注：在同一位置并不一定代表同一漏洞
    def is_loc_same(self, bug):
        if self.testcase_id != bug.testcase_id:
            return False
        if self.sink.file == bug.sink.file:
            if self.sink.line == bug.sink.line:
                return True
        return False

    def copy(self):
        bug = Bug()
        bug.testcase_id = self.testcase_id
        bug.counterexample = self.counterexample
        bug.bug_type = self.bug_type
        bug.severity = self.severity
        bug.description = self.description
        bug.cwe_type = []
        for one in self.cwe_type:
            bug.cwe_type.append(one)
        bug.source = self.source.copy()
        bug.sink = self.sink.copy()
        bug.other_suspicious = []
        for one in self.other_suspicious:
            bug.other_suspicious.append(one.copy())
        bug.execution_path = []
        for one in self.execution_path:
            bug.execution_path.append(one.copy())
        bug.features = []
        for one in self.features:
            bug.features.append(one.copy())
        bug.poc = self.poc
        bug.detection_results = {}
        for key in self.detection_results:
            bug.detection_results[key] = self.detection_results[key]
        return bug

class Testcase():
    def __init__(self):
        self.testcase_id = ""
        self.testcase_dir = ""      # 相对于测试集所在文件夹的相对路径
        self.testcase_dir_abs = ""  # 绝对路径
        self.testsuite_name = ""
        self.compile_command = ""
        self.bugs = []              # 包含的漏洞
        self.domobj = None          # minidom对象

    def copy(self):
        t = Testcase()
        t.testcase_id = self.testcase_id
        t.testcase_dir = self.testcase_dir
        t.testcase_dir_abs = self.testcase_dir_abs
        t.testsuite_name = self.testsuite_name
        t.compile_command = self.compile_command
        t.bugs = []
        t.domobj = None
        return t

    def toXml(self):
        # 创建节点
        dom = minidom.Document()
        testcase_node = dom.createElement("testcase")
        testcase_node.setAttribute('id', self.testcase_id) # 测试样本名称属性
        testcase_node.setAttribute('path', self.testcase_dir) # 测试样本相对路径
        testcase_node.setAttribute('compile_command', self.compile_command) # 测试样本的编译命令
        # 开始添加bug
        for bug in self.bugs:
            bug_node = dom.createElement("bug")
            bug_node.setAttribute('iscounterexample', str(bug.counterexample)) # 是否为反例
            bug_node.setAttribute('type', bug.bug_type) # 漏洞类型
            if len(bug.cwe_type) > 0:                   # 漏洞CWE分类
                cwe_type_str = ""
                for cwe in bug.cwe_type:
                    # 处理一下cwe字符串，统一改为CWE-XXX的格式
                    cwe = "CWE-" + cwe.strip("CWE").strip("cwe").strip("-").strip("_")
                    cwe_type_str = cwe_type_str + "%s|"%(cwe)
                cwe_type_str = cwe_type_str[:-1]
                bug_node.setAttribute('cwe', cwe_type_str)
            # bug的子标签<description>
            desc_node = dom.createElement('description')
            desc_text_node = dom.createTextNode(bug.description)
            desc_node.appendChild(desc_text_node)
            bug_node.appendChild(desc_node)
            # bug的子标签<trace>
            trace_node = dom.createElement('trace')
            source_node = dom.createElement('source')
            source_node.setAttribute('file', bug.source.file)
            source_node.setAttribute('line', str(bug.source.line))
            source_node.setAttribute('col', str(bug.source.col))
            trace_node.appendChild(source_node)
            for location in bug.execution_path:
                location_node = dom.createElement('location')
                location_node.setAttribute('file',location.file)
                location_node.setAttribute('line', str(location.line))
                location_node.setAttribute('col', str(location.col))
                trace_node.appendChild(location_node)
            sink_node = dom.createElement('sink')
            sink_node.setAttribute('file', bug.sink.file)
            sink_node.setAttribute('line', str(bug.sink.line))
            sink_node.setAttribute('col', str(bug.sink.col))
            trace_node.appendChild(sink_node)
            bug_node.appendChild(trace_node)
            # bug的子标签<features>
            features_node = dom.createElement('features')
            for feature in bug.features:
                feature_node = dom.createElement(feature.name)
                feature_desc = dom.createTextNode(feature.description)
                feature_node.appendChild(feature_desc)
                feature_node.setAttribute('capability', feature.capability)
                features_node.appendChild(feature_node)
            bug_node.appendChild(features_node)
            # bug的子标签<detection_results>
            detection_node = dom.createElement('detection_results')
            for tool_name in bug.detection_results.keys():
                tool_node = dom.createElement('tool')
                tool_node.setAttribute('name', tool_name)
                result_txt = dom.createTextNode(bug.detection_results[tool_name])
                tool_node.appendChild(result_txt)
                detection_node.appendChild(tool_node)
            bug_node.appendChild(detection_node)
            # bug的子标签<poc>
            # TBD
            testcase_node.appendChild(bug_node)
        # 把构造好的testcase dom对象放到domobj上
        self.domobj = testcase_node

def gen_manifest(testcases, filename):
    for testcase in testcases:
        testcase.toXml()
    dom = minidom.Document()
    testsuite_node = dom.createElement("testsuite")
    testsuite_node.setAttribute('name', testcases[0].testsuite_name)
    for testcase in testcases:
        testsuite_node.appendChild(testcase.domobj)
    dom.appendChild(testsuite_node)
    with open(filename, "w") as fp:
        dom.writexml(fp, indent="", addindent="    ", newl="\n", encoding="UTF-8")

def parse_manifest(manifest):
    xml_in = open(manifest)
    tree = ET.parse(xml_in)
    root = tree.getroot()
    testsuite_name = root.attrib['name']
    testcases = []
    for testcase_node in root.findall('testcase'):
        testcase = Testcase()
        testcase.testcase_id = testcase_node.attrib['id']
        testcase.testcase_dir = testcase_node.attrib['path']      # 相对于测试集所在文件夹的相对路径
        testcase.testsuite_name = testsuite_name
        testcase.compile_command = testcase_node.attrib['compile_command']
        testcase.bugs = []              # 包含的漏洞
        testcase.domobj = None 
        for bug_node in testcase_node.findall('bug'):
            bug = Bug()
            bug.testcase_id = testcase.testcase_id
            try:
                cwe_type = bug_node.attrib['cwe']
            except Exception as e:
                cwe_type = ""
            bug.cwe_type = cwe_type.split('|')
            bug.bug_type = bug_node.attrib['type']
            bug.counterexample = int(bug_node.attrib['iscounterexample'])
            for child in bug_node:
                if child.tag == "description":
                    bug.description = child.text
                elif child.tag == "trace":
                    for child2 in child:
                        if child2.tag == "source":
                            bug.source.file = child2.attrib['file']
                            bug.source.line = int(child2.attrib['line'])
                            bug.source.col = int(child2.attrib['col'])
                        elif child2.tag == "sink":
                            bug.sink.file = child2.attrib['file']
                            bug.sink.line = int(child2.attrib['line'])
                            bug.sink.col = int(child2.attrib['col'])
                        elif child2.tag == "location":
                            location = Location()
                            location.file = child2.attrib['file']
                            location.line = int(child2.attrib['line'])
                            location.col = int(child2.attrib['col'])
                            bug.execution_path.append(location)
                elif child.tag == "features":
                    for child3 in child:
                        feature = Feature()
                        feature.name = child3.tag
                        feature.description = child3.text
                        if feature.description == None:
                            #当没有text节点时，description会被赋值为None，这里处理一下
                            feature.description = ""
                        feature.capability = child3.attrib['capability']
                        bug.features.append(feature)
                elif child.tag == "detection_results":
                    for child4 in child:
                        bug.detection_results[child4.attrib['name']] = child4.text
            testcase.bugs.append(bug)
        testcases.append(testcase)
    xml_in.close()
    return testcases

# 判断body里面是否包含keywords
wnl = WordNetLemmatizer() # 初始化一次
def __has_keywords(body, keywords):
    num = 0
    for word in body:
        word = wnl.lemmatize(word)
        if word in keywords:
            num = num + 1
    return num    # 返回word中包含keywords的数量


cwe_tree = CWETree(Config.CWEXML)

# 比较个漏洞的漏洞类型是否相同
def bug_type_compare(bug1, bug2):
    # 如果有cwe信息，则先比较cwe信息
    if len(bug1.cwe_type) > 0 and len(bug2.cwe_type) > 0:
        for cwe1 in bug1.cwe_type:
            cwe1 = int(cwe1.split('-')[-1])
            for cwe2 in bug2.cwe_type:
                cwe2 = int(cwe2.split('-')[-1])
                if cwe_tree.hasRelation(cwe1, cwe2):
                    return True
    # 如果有bug_type信息，则比较bug_type信息
    if (len(bug1.bug_type) > 0 and len(bug2.bug_type) > 0) or (len(bug1.description) > 0 and len(bug2.description) > 0):
        bug1.bug_type = bug1.bug_type.replace('_', ' ')
        bug2.bug_type = bug2.bug_type.replace('_', ' ')
        bug1.bug_type = bug1.bug_type.replace('-', ' ')
        bug2.bug_type = bug2.bug_type.replace('-', ' ')
        key_words1 = bug1.bug_type.lower().split(' ')
        key_words2 = bug2.bug_type.lower().split(' ')
        key_words1_ex = bug1.description.split(' ')
        key_words2_ex = bug2.description.split(' ')

        # 选择长度最长的关键词
        chosen_key_words1 = key_words1
        chosen_key_words2 = key_words2
        if (len(chosen_key_words1) < len(key_words1_ex)):
            chosen_key_words1 = key_words1_ex
        if (len(chosen_key_words2) < len(key_words2_ex)):
            chosen_key_words2 = key_words2_ex

        key_words_nullpointer = ['null', 'pointer', 'dereference', 'access']
        key_words_bof = ['over', 'under', 'overflow', 'flow', 'underwrite', 'overread', 'underread', 'out', 'bound', 'read', 'write', 'heap', 'buffer', 'stack', 'array']
        key_words_divide_zero = ['zero', 'divide']
        key_words_integer_overflow = ['integer', 'over', 'flow', 'overflow', 'underflow']
        key_words_format_string = ['format', 'string', 'uncontrol', 'control']

        if 'null' in key_words1 and 'null' in key_words2:
            return True
        if __has_keywords(chosen_key_words1, key_words_nullpointer) >= 2 and \
                __has_keywords(chosen_key_words2, key_words_nullpointer) >= 2:
            return True
        if __has_keywords(chosen_key_words1, key_words_bof) >= 2 and \
                __has_keywords(chosen_key_words2, key_words_bof) >= 2:
            return True
        if __has_keywords(chosen_key_words1, key_words_divide_zero) >= 1 and \
                __has_keywords(chosen_key_words2, key_words_divide_zero) >= 1:
            return True
        if __has_keywords(chosen_key_words1, key_words_integer_overflow) >= 2 and \
                __has_keywords(chosen_key_words2, key_words_integer_overflow) >= 2:
            return True
        if __has_keywords(chosen_key_words1, key_words_format_string) >= 2 and \
                __has_keywords(chosen_key_words2, key_words_format_string) >= 2:
            return True

        print("bug type not same")
        return False

    print("not sure")
    return True


if __name__ == "__main__":
    testcases = parse_manifest(sys.argv[1])
    print(testcases[0].testcase_id)
    gen_manifest(testcases, "ttt")
    for t in testcases:
        for bug in t.bugs:
            for f in bug.features:
                if f.description == None:
                    print(t.testcase_id)
                    exit(0)
