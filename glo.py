import os

class Global:

    CONFIG_TOOLS_HOME = os.path.dirname(os.path.abspath(__file__))
    JULIET_TESTCASESUPPORT = ['io.c', 'main.cpp', 'main_linux.cpp', 'std_testcase.h', 'std_testcase_io.h', 'std_thread.h', 'std_thread.c', 'testcase.h']

    # default language
    LANGUAGE = 'c'

    # path of fake_libc_include of pycparser
    FAKE_LIBC_INCLUDE = '/home/ubuntu/Workspace/pycparser/utils/fake_libc_include'

    # attribute names
    KEY_TESTCASE_ID = 'id'
    KEY_TESTCASE_DIR = 'testcase_dir'
    KEY_ISVUL = 'isvul'
    KEY_VUL_TYPE = 'vul_type'
    KEY_VUL_FILE = 'vul_file'
    KEY_VUL_LINE = 'vul_line'
    KEY_VUL_LOCATION = 'vul_location'
    KEY_LOC = 'lines_of_code'
    KEY_FILE_NUM = 'file_num'
    KEY_FUNC_NUM = 'func_num'
    KEY_LANGUAGE = 'language'
    KEY_GLOBAL_IF_NUM = 'global_if_num'
    KEY_GLOBAL_IF_DEPTH = 'global_if_depth'
    KEY_GLOBAL_FOR_NUM = 'global_for_num'
    KEY_GLOBAL_FOR_DEPTH = 'global_for_depth'
    KEY_GLOBAL_WHILE_NUM = 'global_while_num'
    KEY_GLOBAL_WHILE_DEPTH = 'global_while_depth'
    KEY_GLOBAL_SWITCH_NUM = 'global_switch_num'
    KEY_GLOBAL_SWITCH_DEPTH = 'global_switch_depth'
    KEY_GLOBAL_GOTO_NUM = 'global_goto_num'
    KEY_GLOBAL_ARRDECL_NUM = 'global_arrdecl_num'
    KEY_GLOBAL_ARRDECL_DIMEN = 'global_arrdecl_dimen'
    KEY_GLOBAL_ARRREF_NUM = 'global_arrref_num'
    KEY_GLOBAL_ARRREF_DIMEN = 'global_arrref_dimen'
    KEY_GLOBAL_LONGEST_FCG_PATH = 'global_longest_fcg_path'
    KEY_GLOBAL_EXTERN_NUM = 'global_extern_num'
    KEY_GLOBAL_STRUCTREF_NUM = 'global_structref_num'
    KEY_GLOBAL_STRUCTREF_DEPTH = 'global_structref_depth'
    KEY_GLOBAL_PTRREF_NUM = 'global_ptrref_num'
    KEY_GLOBAL_PTRREF_DEPTH = 'global_ptrref_depth'
    KEY_GLOBAL_FUNCPTR_NUM = 'global_funcptr_num'
    KEY_ONEHOT_VECTOR = 'onehot_vector'


    KEY_IF_NUM = 'if_num'
    KEY_IF_DEPTH = 'if_depth'
    KEY_FOR_NUM = 'for_num'
    KEY_FOR_DEPTH = 'for_depth'
    KEY_WHILE_NUM = 'while_num'
    KEY_WHILE_DEPTH = 'while_depth'
    KEY_SWITCH_NUM = 'switch_num'
    KEY_SWITCH_DEPTH = 'switch_depth'
    KEY_GOTO_NUM = 'goto_num'
    KEY_ARRDECL_NUM = 'arrdecl_num'
    KEY_ARRDECL_DIMEN = 'arrdecl_dimen'
    KEY_ARRREF_NUM = 'arrref_num'
    KEY_ARRREF_DIMEN = 'arrref_dimen'
    KEY_LONGEST_FCG_PATH = 'longest_fcg_path'
    KEY_EXTERN_NUM = 'extern_num'
    KEY_STRUCTREF_NUM = 'structref_num'
    KEY_STRUCTREF_DEPTH = 'structref_depth'
    KEY_PTRREF_NUM = 'ptrref_num'
    KEY_PTRREF_DEPTH = 'ptrref_depth'
    KEY_FUNCPTR_NUM = 'funcptr_num'


class Config:

    HOME = os.path.dirname(os.path.abspath(__file__))
    OUTPUT = HOME + '/' + 'output_tmp'
    LIBS = HOME+'/libs'
    TMP = HOME + '/tmp'
    OPT = LIBS+'/opt2'
    TESTSUITE = HOME + '/testsuite'

class OnehotDict:

    RESERVED_FUNC = []
    
    POINTER_DEREFERENCE = 'pointer_dereference'

    ARRAY_REFERENCE = 'array_reference'

    STRUCT_REFERENCE = 'struct_reference'

    IF = 'if'

    WHILE = 'while'
    DOWHILE = 'while'
    
    FOR = 'for'

    ASSIGNMENT = 'assignment'

    RETURN = 'return'

    DECL = 'decl'

    DECLASSIGNMENT = 'declassignment'

    def __init__(self):
        f = open(Global.CONFIG_TOOLS_HOME + "/onehot_dict")
        for line in f.readlines():
            line = line.strip()
            if line.startswith('#'):
                continue
            if len(line) < 1:
                continue
            self.RESERVED_FUNC.append(line)
            self.RESERVED_FUNC.sort()

