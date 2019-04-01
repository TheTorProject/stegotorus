#!/usr/bin/env python3
# Import the os module, for the os.walk function
import os
import sys
import subprocess

if len(sys.argv) < 2:
    print("Relese folder similar to '0.0.1-20190401' is required")
    print("./tarify_release.py 0.0.1-20190401")
    sys.exit(1)
else:
    current_release = sys.argv[1]

os.chdir('releases/' + current_release)
rootDir = '.'
print(rootDir)
for dirName, subdirList, fileList in os.walk(rootDir):
    num_sep = dirName.count(os.path.sep)
    if num_sep == 2:
        print('taring directory: %s' % dirName)
        subprocess.run(["tar", "cfvz", os.path.basename(dirName) + ".tar.gz", dirName])

        
