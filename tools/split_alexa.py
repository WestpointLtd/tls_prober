#!/usr/bin/python

import sys

max = 14000

if __name__ == '__main__':
    f = open(sys.argv[1])

    chunk = 0
    count = max+1
    out = None

    for line in f:
        if count > max:
            if out is not None:
                out.close()
            count = 0
            chunk += 1
            out = open('chunk-'+str(chunk), 'w')
        
        out.write(line)
        count += 1
