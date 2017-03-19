#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
:author: Maximilian Golla
:contact: maximilian.golla@rub.de
:version: 0.3.0, 2017-03-19

Filter input file to include "American Standard Code for Information Interchange" (ASCII) only.

We filter for non-printable like
\x0b (vertial tab. VT)
\x0c (NP form feed, new page, FF)
\x09 (horizontal tab, TAB)

But we keep a-z, A-Z, 0-9, and all symbols including space
e.g.: # !"#$%&'( )*+,-./\:;?@[]^_`{|}~

Furthermore, we add the following based on the line endings
\x0A (NL line feed, new line, LF)
\x0D (carriage return, CR)

python ascii_filter.py rockyou-all.txt > rockyou-all-ascii.txt
'''

import sys

def is_ascii(s):
    return all(((ord(c) >= 32 and ord(c) <= 126) or ord(c) == 0x0A or ord(c) == 0x0D) for c in s)

removed_counter = 0

# Open file with universal newlines as binary file
with open(str(sys.argv[1]), 'rbU') as passwordfile:
    for line in passwordfile:
        # We remove non utf-8 characters from line, e.g., encoding f*ck up
        line = line.decode('utf-8', 'ignore') # bytes to string
        # Remove newline (Unix '\n', Mac '\r', Windows '\r\n')
        line = line.rstrip('\r\n')
        # Check if printable ASCII
        if is_ascii(line):
            #pass
            print("{}".format(line))
        else:
            # If the line is non-ASCII, we print it to standard error (stderr) stream
            #line = line.encode('utf-8', 'ignore') # string to bytes
            #sys.stderr.write("Removed: {}\n".format(line))
            removed_counter = removed_counter + 1
sys.stderr.write("Done. I removed {} lines/non-ASCII passwords.\n".format(removed_counter))
