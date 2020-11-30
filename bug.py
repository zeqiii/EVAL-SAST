# -*- coding=utf-8 -*-
import json
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

class Feature():
    def __init__(self):
        self.name = ""  # 语法特征名称
        self.description = "" # 描述
        self.capability = "" # 处理该语法特征所需能力

class Location():
    def __init__(self):
        self.file = ""
        self.line = -1
        self.col = -1
    def toString(self):
        loc = {}
        loc["file"] = self.file
        loc["line"] = self.line
        loc["col"] = self.col
        return json.dumps(loc)
    def isEmpty(self):
        if not self.file or self.line < 0:
            return True
        return False
    @staticmethod
    def loads(locstr):
        loc = json.loads(locstr)
        locobj = Location()
        locobj.file = loc["file"]
        locobj.line = loc["line"]
        locobj.col = loc["col"]
        return locobj

class Bug():
    def __init__(self):
        self.testcase_id = ""
        self.testcase_dir = ""
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

    @staticmethod
    def loads(sstr):
        obj = json.loads(sstr)
        bug = Bug()
        bug.testcase_id = obj["testcase_id"]
        bug.testcase_dir = obj["testcase_dir"]
        bug.counterexample = obj["counterexample"]
        bug.bug_type = obj["bug_type"]
        bug.severity = obj["severity"]
        bug.description = obj["description"]
        bug.cwe_type = obj["cwe_type"]
        bug.source = Location.loads(obj["source"]) # 暂时忽略一个漏洞多个source的情况
        bug.sink = Location.loads(obj["sink"])
        other_suspicious = json.loads(obj["other_suspicious"]) # 其它可能会被报出的漏洞点
        for one in other_suspicious:
            bug.other_suspicious.append(Location.loads(one))
        execution_path = json.loads(obj["execution_path"])
        for one in execution_path:
            bug.execution_path.append(Location.loads(one))
        bug.detection_results = obj["detection_results"]
        return bug

    def dumps(self):
        bug = {}
        bug["testcase_id"] = self.testcase_id
        bug["testcase_dir"] = self.testcase_dir
        bug["counterexample"] = self.counterexample
        bug["bug_type"] = self.bug_type
        bug["severity"] = self.severity
        bug["description"] = self.description
        bug["cwe_type"] = self.cwe_type
        bug["source"] = self.source.toString()
        bug["sink"] = self.sink.toString()
        other_suspicious = []
        for one in self.other_suspicious:
            other_suspicious.append(one.toString())
        bug["other_suspicious"] = json.dumps(other_suspicious)
        execution_path = []
        for one in self.execution_path:
            execution_path.append(one.toString())
        bug["execution_path"] = json.dumps(execution_path)
        bug["detection_results"] = self.detection_results
        return json.dumps(bug)

    # 对比本身与参数bug是否代表了同一个漏洞
    def compare(self, bug, tool):
        if self.testcase_id != bug.testcase_id:
            return False
        if self.sink.file == bug.sink.file:
            if self.sink.line == bug.sink.line:
                if not self.counterexample:
                    self.detection_results[tool] = "TP"
                else:
                    self.detection_results[tool] = "FP"
                return True
        return False

class Testcase():
    def __init__(self):
        self.testcase_id = ""
        self.testcase_dir = ""      # 相对于测试集所在文件夹的相对路径
        self.testcase_dir_abs = ""  # 绝对路径
        self.testsuite_name = ""
        self.compile_command = ""
        self.bugs = []              # 包含的漏洞
        self.domobj = None          # minidom对象
    
    def dumps(self):
        testcase = {}
        testcase["testcase_id"] = self.testcase_id
        testcase["testcase_dir"] = self.testcase_dir
        testcase["testsuite_name"] = self.testsuite_name
        testcase["compile_command"] = self.compile_command
        return json.dumps(testcase)

    @staticmethod
    def loads(sstr):
        obj = json.loads(sstr)
        testcase = Testcase()
        testcase.testcase_id = obj["testcase_id"]
        testcase.testcase_dir = obj["testcase_dir"]
        testcase.testsuite_name = obj["testsuite_name"]
        testcase.compile_command = obj["compile_command"]
        return testcase

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
            # bug的子标签<poc>
            # TBD
            testcase_node.appendChild(bug_node)

        # 把构造好的testcase dom对象放到domobj上
        self.domobj = testcase_node


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
        for bug_node in testcase.findall('bug'):
            bug = Bug()
            cwe_type = bug_node.attrib['cwe']
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
                    feature = Feature()
                    feature.name = child.tag
                    feature.description = child.text
                    feature.capability = child.attrib['capability']
                    bug.features.append(feature)
            testcase.bugs.append(bug)
        testcases.append(testcase)
    xml_in.close()
    return testcases
