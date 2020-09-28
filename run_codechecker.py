import os, sys
from impl import *
import subprocess
import codecs
from xml import etree
class Runner_Clang(Runner):
    def __init__(self):
        Runner.__init__(self)
        self.name = "clang-anaylers"
        self.confgi = "" # no config

    def _genCMD(self, testcase_path, language, output_path, output_file):
        if not os.path.exists(testcase_path):
            raise Exception(testcase_path+" does not exist")
        command=[]
	if os.path.isdir(testcase_path):
	    flag_make=0
	    flag_c=0
	    flag_cf=0
            for parent, dirnames, filenames in os.walk(testcase_path):
		
  		#there may have many dir ,so we need to make sure whether there is a file
		if filenames:
		    files=[]
                    for filename in filenames:
                        if filename=="Makefile":
			    flag_make = 1
			    makepath=parent
			elif filename.endswith(".c"):
			    files.append(filename)
			 #   print filename
			    flag_c =1
			    gccpath=parent
			elif filename=="configure":
			    flag_cf=1
			    cfpath=parent
			else:
			    pass
	elif os.path.isfile(testcase_path) and testcase_path.endswith(".c"):
            cmd="scan-build gcc "+testcase_path+" -o tmp"
            return cmd
        else:
            raise Exception(testcase_path+" is not supported")
	if flag_cf==1:
	    cmd="cd "+cfpath+"; scan-build ./configure"
            print cmd
            Runner.lock.acquire()
            os.system(cmd)
            Runner.lock.release()
            cmd3="cd "+cfpath+";scan-build -o "+output_path+output_file+" make"
	    print cmd3
            return cmd3
	elif flag_make==1:
	    f= open(makepath+"/Makefile","r")
 	    lines = f.readlines()
	    gcclines=[]
  	    for line in lines:
  	        if "gcc " in line:
	 	    l=line.index("gcc ")
		    if "; \\" in line:
		        line=line[l:].replace("; \\","").strip('\n')
	  	    else:
		   	line=line[l:].strip('\n')
			line=line.split(" ")
	#		print line
			lt=[]
			for lc in line:
			    if ".c" in lc:
				lc = makepath+"/"+lc.replace("\r","")
				lt.append(lc)
			    else:
				lt.append(lc)
			line=" ".join(lt)
	#		print "gcc : "+ line
			gcclines.append(line)
		else:
		    pass
   #		    print "no use"
		cmd1=""
   	    for gccline in gcclines:
		cmd1+= "scan-build -o "+output_path+output_file+" "+gccline+" ;"	
	#	print cmd1
		return cmd1
	elif flag_c==1:
	    cmd2="scan-build -o "+output_path+output_file+" gcc -c "
	    for file_c in files:
		cmd2+=gccpath+"/"+file_c+" "
		#print cmd2
		return cmd2
	else:
	    pass
	    print "no"
	#cmd=""
	#return cmd
    def _parseOutput(self,output_file):
	try:
	    p=subprocess.check_output("cd "+output_file+";ls -l|grep '^d'|awk '{print $9}'|grep '2*'",shell=True)
	    p=p.split("\n")
	    path=output_file+"/"+p[0]+"/index.html"
	    f=codecs.open(path,"r","utf-8")
            content=f.read()
	    f.close()
	    tree=etree.HTML(content)
 	    nodes=tree.xpath("//tbody//tr//td/text()")
	    urls =tree.xpath("//tbody//tr/td[7]/a/@href")
	    ds=[]
	    for url in urls:
       	    	url=url[:-8]
       	        f=codecs.open(output_file+"/"+p[0]+"/"+url,"r","utf-8")
            	con=f.read()
    	    	f.close()
            	t=etree.HTML(con)
            	des=t.xpath("//table[@class='simpletable']/tr[3]/td[2]/text()")
            	ds.append(des)
	    t=0
	    bug_list=[]
	    for i in range(0,len(nodes),6):
    		b=nodes[i:i+6]
	    	bug=BugResult()
	    	bug.bug_type=b[1]
	    	bug.method =b[3]
		bug.vul_path.append({"filename":b[2], "line":b[4]})
	    	bug.description=ds[t][0]
	    	t=t+1
	    	bug_list.append(bug)
	except Exception,e:
	    #print "no bug"
	    bug_list=[]
	return bug_list

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "error!"
    json_param = sys.argv[1]
    csa = Runner_Clang()
    csa.init(json_param)
    csa.download()
    csa.start()
    csa.parse()
    csa.compare()
    csa.update()
