#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
:author: Maximilian Golla
:contact: maximilian.golla@rub.de
:version: 0.3.1, 2018-12-25

Reverse withcount format produced by "uniq -c"
Output of this script needs to be shuffled again via "shuf"

python reverse_withcount.py rockyou-withcount.txt > rockyou-all.txt
'''

import sys, re

# Visit pythex.org to get the idea
pw_re = re.compile('^\s*[0-9]*\s')
occ_re = re.compile('^\s*[0-9]*')

# Open file with universal newlines
with open(sys.argv[1], 'rU') as passwordfile:
    for line in passwordfile:
        # Remove newline (Unix '\n', Mac '\r', Windows '\r\n')
        line = line.rstrip('\r\n')
        try:
            # Replace everything but the password with empty string
            pw = line.replace(pw_re.findall(line)[0], '')
            # Get counter, replace spaces with empty string, like strip()
            occ = int(occ_re.findall(line)[0].replace(' ', ''))
            # Print password for (counter)-times
            for o in range(0, occ):
                print("{}".format(pw))
        except:
            # If something goes wrong, print to standard error (stderr) stream
            sys.stderr.write("Error: {}\n".format(line))
