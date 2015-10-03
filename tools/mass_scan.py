#!/usr/bin/python

import sys
import os

cmd = './tls_prober/prober.py -l %s > results/%s_%s.fp'

if __name__ == '__main__':
    f = open(sys.argv[1])
    for line in f:
        line = line[:-1]
        ip, domain = line.split(',')
        print ip, domain

        os.system(cmd % (ip, ip, domain))


