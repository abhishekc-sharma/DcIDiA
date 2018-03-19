from __future__ import print_function
from sets import Set
import re
import sys
import os
import subprocess

try:  
   os.environ["MARA_PATH"]
except KeyError: 
   print("Please set the environment variable MARA_PATH")
   sys.exit(1)

mara_path = os.environ["MARA_PATH"]

sys.argv[1]
