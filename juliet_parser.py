# -*- coding=utf-8 -*-
import os, sys, zipfile, shutil
from glo import *
from bug import *


tool = os.path.join(Config.LIBS, "tooling_sample")
f_fun_info = os.path.join(Config.TMP, "func_line.info")

# gen function line info using libtooling
def gen_func_info(sourcefile):
    # -DINCLUDEMAIN 是为了适配juliet的编译而增加的预定义宏
    cmd = "%s %s -extra-arg=\"-DINCLUDEMAIN -I%s\" > %s 2>/dev/null"%(tool, sourcefile, os.path.dirname(sourcefile), f_fun_info)
    os.system(cmd)
    f = open(f_fun_info)
    lines = f.readlines()
    f.close()
    return lines


def parse_func_info(lines, filters=[]):
    # {
    #  filename: 
    #  {fun_name1: (startline, endline), fun_name2: (startline, endline)}
    # }
    info = {}
    for line in lines:
        funname = line.split("#")[0]
        funinfo = line.split("#")[1]
        if funinfo.find("/usr") > 0:
            continue
        for one in filters:
            if funinfo.find(one) < 0:
                continue
        funinfo = funinfo.split(":")
        filepath = funinfo[1]
        if filepath not in info.keys():
            info[filepath] = {}
        if funname not in info[filepath].keys():
            info[filepath][funname] = {}
        linenum = funinfo[2]
        info[filepath][funname][funinfo[0]] = linenum
    return info


def create_single_testcase(juliet_home_dir, outdir, cwe_list=[], preprocessed_bugs=None):
    support_files = ["io.c", "std_testcase.h", "std_testcase_io.h", "std_thread.c", "std_thread.h"]
    
    # copy support file to pwd
    for i in range(len(support_files)):
        f = support_files[i]
        support_files[i] = os.path.join(os.path.join(juliet_home_dir, "testcasesupport"), f)
    
    # get dir list in ./testcases
    testcases_cwe_list = []
    testcases_dir = os.path.join(juliet_home_dir, "testcases")
    for one in os.listdir(testcases_dir):
        if len(cwe_list) == 0:
            for cwe in cwe_list:
                testcases_cwe_list.append(os.path.join(testcases_dir, one))
        else:
            for cwe in cwe_list:
                if one.find(cwe) >= 0:
                    testcases_cwe_list.append(os.path.join(testcases_dir, one))
                    break

    testcases = []

    # get files for one test case
    for one in testcases_cwe_list:
        # fetch source files in one cwe dir
        file_list = []
        for parent, dirnames, files in os.walk(one):
            for f in files:
                # omit useless files
                if not (f.endswith(".c") or f.endswith(".cpp") or f.endswith(".h")) or f == "main.cpp" or f == "testcases.h" or f == "main_linux.cpp":
                    pass
                else:
                    file_list.append(os.path.join(parent, f))
        # init signature-filename map
        sig_file_map = {}
        for fpath in file_list:
            f = os.path.basename(fpath)
            # fetch signature from filename
            # e.g. CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_connect_socket_66b.cpp
            # e.g. part_2 = 66b.cpp
            part_2 = f.split("_")[-1]
            if part_2.startswith("good") or part_2.startswith("bad"):
                part_2 = f.split("_")[-2]
            # e.g. num = 66
            num = part_2[0:2]
            # a signature represents a test case
            # e.g. signature = CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_connect_socket_66
            signature = f.split("_"+num)[0] + "_" + num
            # store signature into map key
            # store filename into map value
            if signature not in sig_file_map.keys():
                sig_file_map[signature] = []
            sig_file_map[signature].append(fpath)

        #对于每一个cwe类型的testcases，在outdir下创建一个目录，目录名取"__"的前半部分，即CWE名
        #然后把testcase存在这个目录下
        # move to outdir
        testcases = []
        for sig in sig_file_map.keys():
            testcase = Testcase()
            the_bug = None
            for bug in preprocessed_bugs:
                if sig == bug.testcase_id:
                    the_bug = bug
                    break
            # save path
            outpath = os.path.join(outdir, sig.split("__")[0])
            outpath = os.path.join(outpath, sig)
            testcase.testcase_dir = os.path.abspath(outpath)
            testcase.testcase_id = sig
            testcase.testsuite_name = "juliet"
            testcase.compile_command = "clang -DINCLUDEMAIN -lpthread *.c"
            if not os.path.exists(outpath):
                os.makedirs(outpath)
            # cp file to outdir
            files = sig_file_map[sig]
            for f in support_files:
                shutil.copy(f, outpath)
            for f in files:
                if f.endswith(".cpp"):
                    testcase.compile_command = "clang++ -DINCLUDEMAIN -lpthread *.cpp *.c"
                shutil.copy(f, outpath)
            if the_bug:
                with open(os.path.join(outpath, "testcase_metadata"), "w") as fp:
                    fp.write(the_bug.dumps())
            testcases.append(testcase)
    return testcases


def parse_juliet_func_info(lines, filters=[]):
    # {
    #  filename: 
    #  {fun_name1: (startline, endline), fun_name2: (startline, endline)}
    # }
    info = {}
    for line in lines:
        funname = line.split("#")[0]
        funinfo = line.split("#")[1]
        if funname.find("bad") < 0 and funname.find("good") < 0 and funname.find("Good") < 0 and funname.find("Bad") < 0:
            continue
        if funinfo.find("/usr") > 0:
            continue
        for one in filters:
            if funinfo.find(one) < 0:
                continue
        funinfo = funinfo.split(":")
        filepath = funinfo[1]
        if filepath not in info.keys():
            info[filepath] = {}
        if funname not in info[filepath].keys():
            info[filepath][funname] = {}
        linenum = funinfo[2]
        info[filepath][funname][funinfo[0]] = linenum
    return info


def parse_juliet_vul_info(testcase_dir):
    func_infos = []
    # extract func info
    for f in os.listdir(testcase_dir):
        if f.startswith("CWE") and (f.endswith(".cpp") or f.endswith(".c")):
            lines = gen_func_info(os.path.join(testcase_dir, f))
            func_info = parse_juliet_func_info(lines, filters=[testcase_dir])
            if func_info == {}:
                continue
            func_infos.append(func_info)

    vuls = []
    # parse func info
    for info in func_infos:
        files = info.keys()
        for f in files:
            fp = open(f)
            lines = fp.readlines()
            fp.close()
            func_info = info[f]
            for func_name in func_info.keys():
                line_info = func_info[func_name]
                start_line = line_info["funcstartline"]
                end_line = line_info["funcendline"]
                if int(end_line) <= int(start_line):
                    continue
                func_body = lines[int(start_line)-1: int(end_line)]
                # find key word from func body, record line num
                flag = -1 # -1: no bug; 1: bug; 0: counterexample
                for i in range(0, len(func_body)):
                    last_part_func_name = func_name.split('_')[-1]
                    # handle the situation where func name is like "goodG2BSink_b" etc.
                    if len(last_part_func_name) < 2:
                        if len(func_name.split('_')) > 1:
                            tmp = func_name.split('_')[-2]
                            if tmp.startswith("bad") or tmp.startswith("good"):
                                last_part_func_name = tmp
                    if (last_part_func_name.startswith("bad") or last_part_func_name.endswith("bad") \
                            or last_part_func_name.endswith("Bad")) \
                            and (func_body[i].find("/* FLAW:")>=0 or func_body[i].find("/* POTENTIAL FLAW")>=0):
                        vul_sig = last_part_func_name.split("bad")[-1]
                        vul_sig = vul_sig.split("Sink")[0]
                        vul_sig = vul_sig.split("Source")[0]
                        vul_sig = "bad" + vul_sig
                        flag = 1
                        continue
                    elif (last_part_func_name.startswith("good") or last_part_func_name.endswith("good") \
                            or last_part_func_name.endswith("Good")) \
                            and (func_body[i].find("/* FLAW:")>=0 or func_body[i].find("/* POTENTIAL FLAW")>=0):
                        vul_sig = last_part_func_name.split("good")[-1]
                        vul_sig = vul_sig.split("Sink")[0]
                        vul_sig = vul_sig.split("Source")[0]
                        vul_sig = "good" + vul_sig
                        flag = 0
                        continue
                    elif func_body[i].find("/* FIX:")>=0:
                        vul_sig = last_part_func_name.split("good")[-1]
                        vul_sig = vul_sig.split("Sink")[0]
                        vul_sig = vul_sig.split("Source")[0]
                        vul_sig = "good" + vul_sig
                        flag = 0
                        continue
                    elif flag >=0 and (func_body[i].strip().startswith("*") or func_body[i].strip().startswith("/")):
                        continue
                    elif flag >=0 and (func_body[i].strip()=="{" or func_body[i].strip()=="}"):
                        continue
                    elif flag >=0 and func_body[i].strip().startswith("if ("):
                        continue
                    elif flag >=0 and func_body[i].strip().startswith("for ("):
                        continue
                    elif flag >=0 and func_body[i].strip().startswith("while("):
                        continue
                    elif flag >=0:
                        vuls.append({"filename":os.path.abspath(f), "funcname":func_name, "line":str(i + int(start_line)), "isvul":flag, "signature":vul_sig})
                        flag = -1
    return vuls



if __name__ == "__main__":

    vuls = parse_juliet_vul_info("/home/ubuntu/Workspace/NeuEval/benchmark/testsuite2/CWE369_Divide_by_Zero/CWE369_Divide_by_Zero__int_zero_modulo_44")
    print(vuls)
