import pymysql, threading
from glo import *

class DBUtil:
    conn = None
    cursor = None
    lock = threading.Lock()
    def __init__(self):
        DBUtil.conn = None
        DBUtil.cursor = None
        self.connected = False
    def connect(self):
        try:
            DBUtil.conn = pymysql.connect(Config.db_addr, Config.db_user, Config.db_pwd, Config.db_name)
            DBUtil.conn.set_character_set('utf8')
            DBUtil.conn.ping(True)
            DBUtil.cursor = self.conn.cursor()
            self.connected = True
        except Exception as e:
            DBUtil.conn = None
            DBUtil.cursor = None
            print("DBUtil, connect failed")
    def disconnect(self):
        try:
            DBUtil.cursor.close()
            DBUtil.conn.close()
            self.connected = False
        except Exception as e:
            print("DBUtil: disconnect error")

    def insert_testcase(self, testcases):
        if not self.connected:
            self.connect()
        for testcase in testcases:
            sql = "insert into eval_testcase set testcase_id='%s', testsuite_name='%s', testcase_dir='%s', compile_command='%s'" \
            %(testcase.testcase_id, testcase.testsuite_name, testcase.testcase_dir, testcase.compile_command)
            try:
                DBUtil.lock.acquire()
                self.cursor.execute(sql)
            except Exception as e:
                print("error insert testcase")
            finally:
                DBUtil.lock.release()
        self.disconnect()

    def insert_groundtruth_bug(self, testcases):
        if not self.connected:
            self.connect()
        for testcase in testcases:
            for bug in testcase.bugs:
                locations = []
                for location in bug.execution_path:
                    locations.append(location.toString())
                features = []
                for feature in bug.features:
                    features.append(feature.name)
                sql = "insert into eval_groundtruth_bug set testcase_id='%s', counterexample=%d, bug_type='%s' \
                    severity='%s' , description='%s', cwe_type='%s', source='%s', sink='%s', execution_path='%s'\
                    features='%s', poc='%s', detection_results='%s'" \
                %(pymysql.escape_string(testcase.testcase_id), bug.counterexample, pymysql.escape_string(bug.bug_type), \
                    pymysql.escape_string(bug.severity), pymysql.escape_string(bug.description), pymysql.escape_string(str(bug.cwe_type)), \
                    pymysql.escape_string(bug.source.toString()), pymysql.escape_string(bug.sink.toString()), \
                    pymysql.escape_string(str(locations)), pymysql.escape_string(str(features)), pymysql.escape_string(bug.poc), \
                    pymysql.escape_string(str(bug.detection_results)))
                try:
                    DBUtil.lock.acquire()
                    self.cursor.execute(sql)
                except Exception as e:
                    print("error insert testcase")
                finally:
                    DBUtil.lock.release()
        self.disconnect()
