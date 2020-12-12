import MySQLdb, threading
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
            DBUtil.conn = MySQLdb.connect(Config.db_addr, Config.db_user, Config.db_pwd, Config.db_name)
            DBUtil.conn.set_character_set('utf8')
            DBUtil.conn.ping(True)
            DBUtil.cursor = self.conn.cursor()
            self.connected = True
        except Exception, e:
            DBUtil.conn = None
            DBUtil.cursor = None
            print("DBUtil, connect failed")
    def disconnect(self):
        try:
            DBUtil.cursor.close()
            DBUtil.conn.close()
            self.connected = False
        except Exception, e:
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
            except Exception, e:
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
                    features='%s', poc='%s', detection_results='%s'"
                %(MySQLdb.escape_string(testcase.testcase_id), bug.counterexample, MySQLdb.escape_string(bug.bug_type), \
                    MySQLdb.escape_string(bug.severity), MySQLdb.escape_string(bug.description), MySQLdb.escape_string(bug.cwe_type)\
                    MyQSLdb.escape_string(bug.source.toString()), MySQLdb.escape_string(bug.sink.toString()), \
                    MySQLdb.escape_string(str(locations)), MySQLdb.escape_string(features.toString()), MySQLdb.escape_string(bug.poc)\
                    MySQLdb.escape_string(str(bug.detection_results)))
                try:
                    DBUtil.lock.acquire()
                    self.cursor.execute(sql)
                except Exception, e:
                    print("error insert testcase")
                finally:
                    DBUtil.lock.release()
        self.disconnect()