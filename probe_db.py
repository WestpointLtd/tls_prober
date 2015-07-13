#!/usr/bin/python

import sys
import glob
import string
import os.path

fingerprint_dir = os.path.join(os.path.dirname(__file__), 'fingerprints')

class Fingerprint(object):
    def __init__(self, metadata, probes):
        self.metadata = metadata
        self.probes = probes

    def description(self):
        return self.metadata['Description']

def read_fingerprint(filename):
    f = open(filename)

    in_body = False
    probes = {}
    metadata = {}

    for line in f:
        line = line.strip()

        if line.startswith('#'):
            continue
        if in_body:
            key, value = line.split(':',1)
            probes[key] = value.strip()
        elif line == '':
            in_body = True
        else:
            key, value = line.split(':',1)
            metadata[key] = value.strip()

    f.close()
    return Fingerprint(metadata, probes)

def read_database():
    database = []

    for f in glob.glob(os.path.join(fingerprint_dir, '*.fp')):
        fingerprint = read_fingerprint(f)
        database += [fingerprint]

    return database

def find_matches(probes):
    scores = {}

    database = read_database()
    for f in database:
        for key in probes.keys():
            if f.probes.has_key(key) and f.probes[key] == probes[key]:
                scores[f.description()] = scores.get(f.description(), 0)+1

    # Remove entries that don't match at all
    for desc in scores.keys():
        if scores[desc] == 0:
            del scores[desc]

    # Convert the matches to a list
    results = []
    matches = sorted(scores, key=scores.__getitem__, reverse=True)
    for match in matches:
        results += [ [match, scores[match]] ]

    return results

def add_fingerprint(description, probes):
    # Create filename
    filename = description.translate(None, string.punctuation)
    filename = filename.strip()
    filename = filename.replace(' ', '-')
    filename = filename.lower()
    filename += '.fp'

    f = open(os.path.join(fingerprint_dir, filename), 'w')
    f.write('Description: %s\n' % description)
    f.write('\n')
    for probe in probes.keys():
        f.write('%s: %s\n' % (probe, probes[probe]))
    f.close()

    return os.path.join(fingerprint_dir, filename)

if __name__ == '__main__':
    database = read_database()

    for fingerprint in database:
        print 'Description:'
        print fingerprint.description()
        print 'Metadata:'
        print fingerprint.metadata
        print 'Probes:'
        print fingerprint.probes


    matches = find_matches(database[0].probes)
    print matches


