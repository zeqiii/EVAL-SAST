import os, threading, json, shutil, time, traceback
from glo import Config
from dao import *
from CWE import *

CWETREE = CWETree("cwe-1000.xml")

class BugResult:
    def __init__(self):
        self.ID = -1
        self.testcase_id = ""
        self.is_vul = 0
        self.severity = ""       # severity: info, low, medium, high, critical
        self.description = ""
        self.bug_type = ""
        self.cwe_type = []       # example: [193, 122] 一个bug可能同时属于多种CWE
        self.vul_path = []       # [{"filename": "xxx", "line": "xx"}, ...]  字典 '{文件, 行号}' 的列表

    # 对比自身和参数bug是否表示的是同一个漏洞
    def equal(self, bug):
        if len(bug.cwe_type) > 0 and len(self.cwe_type) > 0:
            b = False
            for i in self.cwe_type:
                for j in bug.cwe_type:
                    if CWETREE.hasRelation(i,j):
                        b = True
                        break
                if b:
                    break
            if not b:
                return b

        for i in self.vul_path:
            for j in bug.vul_path:
                #if os.path.basename(i["filename"]) == os.path.basename(j["filename"]) and abs(int(i["line"]) - int(j["line"])) <= 2:
                if os.path.basename(i["filename"]) == os.path.basename(j["filename"]) and int(i["line"]) == int(j["line"]):
                    return True
        return False

    # print
    def toString(self):
        info = {}
        info['bug_type'] = self.bug_type
        info['cwe'] = self.cwe_type
        info['vul_path'] = self.vul_path
        return json.dumps(info)


def get_testcase_path(testcase_id, testsuite_home_dir=Config.TESTSUITE):
    for parent, dirs, files in os.walk(testsuite_home_dir):
        parent = os.path.abspath(parent)
        for d in dirs:
            if d == testcase_id and parent.find(os.path.abspath(Config.OUTPUT)) < 0:
                return os.path.abspath(os.path.join(parent, d))
    return None


class Runner:

    # 1，从数据库查询testcase                       # 1，运行工具输出结果
    # 2，根据testcase id定位testcase path           # 2，分析结果
    # 3，调用工具输出结果                           # 3，更新数据库
    # 4，分析结果
    # 5，更新数据库

    # GLOBAL VARIANTS
    lock = threading.Lock()           # for thread safe operation

    def __init__(self):
        self.db = DBUtil()
        self.tool = ""                # tested tool's name
        self.testcases = {}           # set of testcase, {testcase_name: (testcase_path, language)}
        self.tooloutputs = {}         # set of tool's output, {testcase_name:output_file}
        self.has_tested = False       # flag to see if testing has been finished
        self.has_parsed = False       # flag to see if parsing has been finished
        if not os.path.exists(Config.TMP):
            os.makedirs(Config.TMP)
        if not os.path.exists(Config.OUTPUT):
            os.makedirs(Config.OUTPUT)

    # 适合于测试样本数量不多，或者分析工具对单个小样本的检测执行速度快的情景
    def start(self):
        while True:
            vul_list = self._select_from_DB(100)
            ####vul_list = self._select_from_DB2()
            if not vul_list:
                break
            if len(vul_list) == 0:
                break
            for _id, testcase_id, is_vul, vul_type, vul_location in vul_list:
                testcase_path = get_testcase_path(testcase_id)
                if testcase_path == None:
                    continue
                output = self.start_one(testcase_path, Config.OUTPUT, testcase_id)
                #print('start_one finished, output=%s' %(output))
                bugs = self._parseOutput(output) # detected bugs by tools
                real_bug = BugResult()        # real bug
                real_bug._ID = _id
                real_bug.is_vul = is_vul
                for vul_info in vul_location.split('#'):
                    vul_info = vul_info.split(':')
                    real_bug.vul_path.append({"filename":vul_info[0], "line":vul_info[1]})
                result, the_bug = self.judge(real_bug, bugs)
                print('updating...')
                self._update(_id, result, details=bugs)
            self.__clean()

            ###
            print("update complete")
            break
            ###
        self.db.disconnect()

    # 适合分析工具对单个小样本检测执行速度慢的情景，如checkmarx
    def start2(self, testcase_path, testsuite_name):
        testcase_path = os.path.abspath(testcase_path)
        bugs = []
        if self.tool == "checkmarx":
            print("start2, tool=checkmarx")
            output = self.start_one(testcase_path, Config.HOME, 'cx_out_%s.xml' %(testsuite_name))
            ####output = os.path.abspath('../detection_results/checkmarx/cx_out_%s.xml' %(testsuite_name))
            print("output=%s , start parsing..." %(output))
            bugs = self._parseOutput(output, testsuite_name)
            print("%d bugs in total" %len(bugs))
        else:
            pass
        
        result_update_info = {}
        for bug in bugs:
            # 查询相同testcase_id的bug记录
            sql_str = "select _id, testcase_id, is_vul, vul_location from neueval_testcases where testcase_id='%s'" %(bug.testcase_id)
            self.db.connect()
            self.db.cursor.execute(sql_str)
            results = self.db.cursor.fetchall()
            for result in results:
                real_bug = BugResult()
                real_bug._ID = result[0]
                real_bug.testcase_id = result[1]
                real_bug.is_vul = result[2]
                for vul_info in result[3].split('#'):
                    vul_info = vul_info.split(':')
                    real_bug.vul_path.append({'filename':vul_info[0], 'line':vul_info[1]})
                detection_result, the_bug = self.judge(real_bug, bugs)
                if real_bug._ID not in result_update_info.keys():
                    result_update_info[real_bug._ID] = (detection_result, the_bug)
                elif detection_result == "TP":
                    result_update_info[real_bug._ID] = (detection_result, the_bug)
                elif detection_result == "FP":
                    detection_result_orig, the_bug_orig = result_update_info[real_bug._ID]
                    if detection_result_orig == "FN" or detection_result_orig == "TN":
                        result_update_info[real_bug._ID] = (detection_result, the_bug)
        for _ID in result_update_info.keys():
            detection_result, the_bug = result_update_info[_ID]
            self._update(_ID, detection_result, details=[the_bug])
        self.db.disconnect()

    # invoke tool to run over one test case
    def start_one(self, testcase_path, output_path, output_file):
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        # gen cmd
        output = os.path.join(output_path, output_file)
        cmd = self._genCMD(testcase_path, output)
        # run cmd to call tool
        Runner.lock.acquire()
        try:
            os.system(cmd)
        except Exception as e:
            exstr = traceback.format_exc()
            print(exstr)
            print(str(e))
        Runner.lock.release()
        return output # return output path

    def judge(self, real_bug, bugs):
        # see if there exists one bug match the real bug
        for bug in bugs:
            if real_bug.equal(bug):
                if real_bug.is_vul == 1:
                    return "TP", bug
                elif real_bug.is_vul == 0:
                    return "FP", bug
        if real_bug.is_vul == 0:
            return "TN", None
        else:
            return "FN", None

    # clean result
    def __clean(self):
        print("cleaning...")
        shutil.rmtree(Config.OUTPUT)
        os.makedirs(Config.OUTPUT)
        shutil.rmtree(Config.TMP)
        os.makedirs(Config.TMP)
        files = os.listdir(Config.HOME)
        for f in files:
            if f.endswith(".o") or f.endswith(".class"):
                os.remove(os.path.join(Config.HOME, f))

    # generate cmd based on testcase_path and output_path, in order to call tools
    # please rewrite this method
    def _genCMD(self, testcase_path, language, output_path, output_file):
        return ""

    # select vuls from DB
    # please rewrite this method
    def _select_from_DB(self, num):
        pass

    # parse output data, return a list of Bug objects
    # please rewrite this method
    def _parseOutput(self):
        return None

    # update DB
    # please rewrite this method
    def _update(self, _id, result, details=[]):
        pass
