from sets import Set
import re
import sys
import os

sosiClassDict = {}
for i in range(1, len(sys.argv)):
    input_file = sys.argv[i]
    with open(input_file) as f:
        for line in f:
            parts = re.compile("[<:\s(),>]").split(line)
            parts = [part for part in parts if len(part) > 0]
            if len(parts) <= 1:
                continue
            className = parts[0]
            methodName = parts[2]
            if not (className in sosiClassDict):
                sosiClassDict[className] = Set([])
            sosiClassDict[className].add(methodName)
#print sosiClassDict
for root, dirs, files in os.walk("."):
    for name in files:
        if re.match("sorted.*",name):
            lineset = set()
            cur = open(name,"r")
            final = open("final"+name,"w+")
            cur1 = cur.readlines()
            for x in cur1:
            	if(len(x.split(":")) > 1):
                    cname = str(re.findall("\w+",x.split(":")[0])).translate(None,'[],\'').replace(" ",".")
                    mname = str(re.findall("\w+",x.split(":")[1])).translate(None,'[],\'')
                    if(cname in sosiClassDict):
                        for y in sosiClassDict[cname]:
                            if y == mname:
                                flag = 0
                                finwrite = cname+" : "+mname+'\n'
                                if finwrite not in lineset:
                                    final.write(finwrite)
                                    lineset.add(finwrite)