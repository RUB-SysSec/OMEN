#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
:author: Maximilian Golla
:contact: maximilian.golla@rub.de
:version: 0.3.0, 2017-03-19

Filter input file for passwords that are 16 characters or less in length.
This is required for some guessers like John the Ripper 'Markov' mode
and PCFG, which have problems with very long passwords.

python length_filter.py rockyou-all-ascii.txt > rockyou-all-ascii-length.txt
'''

import sys

removed_counter = 0

# Open file with universal newlines
with open(str(sys.argv[1]), 'rU') as passwordfile:
    for line in passwordfile:
        # Remove newline (Unix '\n', Mac '\r', Windows '\r\n')
        line = line.rstrip('\r\n')
        # Check if length of pw is 16 or less
        if len(line) <= 16:
            #pass
            print("{}".format(line))
        else:
            #sys.stderr.write("Removed: {}\n".format(line))
            removed_counter = removed_counter + 1
sys.stderr.write("Done. I removed {} passwords.\n".format(removed_counter))
