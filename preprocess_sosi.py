from sets import Set
import re
import sys


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
