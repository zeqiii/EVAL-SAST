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
            if not self.connected:
                DBUtil.conn = pymysql.connect(Config.db_addr, Config.db_user, Config.db_pwd, Config.db_name, charset='utf8')
                DBUtil.conn.ping(True)
                DBUtil.cursor = self.conn.cursor()
                self.connected = True
        except Exception as e:
            DBUtil.conn = None
            DBUtil.cursor = None
            self.connected = False
            print("DBUtil, connect failed")
            print(str(e))
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
                print(str(e))
            finally:
                DBUtil.lock.release()
        self.conn.commit()

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
                sql = "insert into eval_groundtruth_bug set testcase_id='%s', counterexample=%d, bug_type='%s', \
                    severity='%s', description='%s', cwe_type='%s', source='%s', sink='%s', execution_path='%s', \
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
                    print("error insert bug")
                    print(str(e))
                finally:
                    DBUtil.lock.release()
        self.conn.commit()

    def update_testsuite(name=args.name, download_url=args.name+".zip", type=_type):
        if not self.connected:
            self.connect()
        # 检查是否是更新
        sql = "select * from eval_testsuite where testsuite_name='%s'" %(pymysql.escape_string(name))
        self.cursor.execute(sql)
        result = self.cursor.fetchall()
        if len(result) <= 0:
            sql = "insert into eval_testsuite set testsuite_name='%s', download_url='%s', type=%d" \
            %(pymysql.escape_string(name), pymysql.escape_string(download_url), type)
            self.cursor.execute(sql)
        else:
            sql = "update eval_testsuite set download_url='%s', type=%d where testsuite_name='%s'" \
            %(pymysql.escape_string(download_url), type, pymysql.escape_string(name))
            self.cursor.execute(sql)
        self.conn.commit()