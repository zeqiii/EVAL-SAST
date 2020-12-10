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
            print "DBUtil, connect failed"
    def disconnect(self):
        try:
            DBUtil.cursor.close()
            DBUtil.conn.close()
            self.connected = False
        except Exception, e:
            print "DBUtil: disconnect error"