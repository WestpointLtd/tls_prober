#!/bin/bash

for f in targets/chunk*
do
    ./mass_scan.py $f &
done
