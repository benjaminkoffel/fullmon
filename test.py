#!/usr/bin/env python3
import agent
import auditd

def test():
    b, a = agent.initialize(), agent.initialize()
    print('data/baseline.log')
    with open('data/baseline.log', 'r') as f:
        for l in f.readlines():
            auditd.collect(l, lambda x: agent.record(b, x))
    print('data/actual.log')
    auditd.collect.buffer = []
    with open('data/actual.log', 'r') as f:
        for l in f.readlines():
            auditd.collect(l, lambda x: agent.record(a, x))
    # bp = '\n'.join(sorted(['->'.join(v.attributes['id'] for v in p) for p in b.list_paths()]))
    # ap = '\n'.join(sorted(['->'.join(v.attributes['id'] for v in p) for p in a.list_paths()]))
    # print('BASELINE:')
    # print(bp)
    # print('ACTUAL:')
    # print(ap)
    # print('TEST:', bp == ap)
    print('compare')
    agent.compare(b, a)

test()
