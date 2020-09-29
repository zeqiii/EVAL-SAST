# -*- coding=utf-8 -*-
import json

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
        self.cwe_type = []       # example: [193, 122]
        self.source = Location()
        self.sink = Location()
        self.execution_path = [] # array of Location

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
        bug.execution_path = obj["execution_path"]
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
        bug["execution_path"] = self.execution_path
        return json.dumps(bug)

class Testcase():
    def __init__(self):
        self.testcase_id = ""
        self.testcase_dir = ""
        self.testsuite_name = ""
        self.compile_command = ""
    
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
