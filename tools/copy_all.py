#!/usr/bin/env python

import sys, subprocess

f = open(sys.argv[1])

for cur_file in f:
    print cur_file, "..."
    subprocess.Popen(['cp', cur_file[:-1], sys.argv[2]])
    
