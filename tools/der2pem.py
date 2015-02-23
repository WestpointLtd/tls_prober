#!/usr/bin/python

import sys
import base64

def split_by_n( seq, n ):
    """A generator to divide a sequence into chunks of n units."""
    while seq:
        yield seq[:n]
        seq = seq[n:]

if __name__ == '__main__':
    f = open(sys.argv[1])
    der = f.read()
    f.close()

    b64 = base64.b64encode(der)

    for line in split_by_n(b64, 64):
        print line



