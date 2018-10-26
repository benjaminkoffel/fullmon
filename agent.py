#!/usr/bin/env python3
import collections
import datetime
import sys
import auditd
import graphdb

BASELINE_SECONDS = 5
DETECT_SECONDS = 1
MIN_PATH_LENGTH = 1

def initialize():
    graph = graphdb.graph()
    graph.add_index('id')
    graph.add_index('process.pid')
    return graph

def record(graph, events):
    for event in events:
        if event['type'] == 'process':
            A = graph.find_vertices('process.pid', event['ppid'])
            if not A:
                A = [graph.add_vertex({
                    'id': 'proc::',
                    'process.pid': event['ppid']})]
            for a in A:
                b = graph.add_vertex({
                    'id': 'proc:{}:{}'.format(event['uid'], event['exe']),
                    'process.pid': event['pid']})    
                graph.add_edge(a, b, {})
                print('+exec')
        elif event['type'] == 'filemod':
            for a in graph.find_vertices('process.pid', event['pid']):
                b = graph.add_vertex({
                    'id': 'file:{}:{}'.format(event['action'], event['path'])})
                graph.add_edge(a, b, {})
                print('+filemod')
        elif event['type'] == 'netconn':
            for a in graph.find_vertices('process.pid', event['pid']):
                b = graph.add_vertex({
                    'id': 'host:{}:{}'.format(event['ip'], event['port'])})
                graph.add_edge(a, b, {})
                print('+netconn')

def compare(baseline, actual):
    paths = actual.list_paths()
    for path in paths:
        pruned = [p for p in path if p.attributes['id'] != 'proc::']
        if len(pruned) >= MIN_PATH_LENGTH:
            if not baseline.has_path(pruned, 'id'):
                print('WARNING:', '->'.join(v.attributes['id'] for v in pruned))

def main():
    try:
        baseline, actual = initialize(), initialize()
        state, init = 'baseline', datetime.datetime.now()
        for line in sys.stdin:
            now = datetime.datetime.now()
            # state transitions
            if state == 'baseline' and (now - init).seconds > BASELINE_SECONDS:
                state, init = 'collect', datetime.datetime.now()
                print(state, init)
            elif state == 'collect' and (now - init).seconds > DETECT_SECONDS:
                state, init = 'detect', datetime.datetime.now()
                print(state, init)
            elif state == 'detect':
                state, init = 'collect', datetime.datetime.now()
                print(state, init)
            # perform work
            if state == 'baseline':
                auditd.collect(line, lambda x: record(baseline, x))
            elif state == 'collect':
                auditd.collect(line, lambda x: record(actual, x))
            elif state == 'detect':
                compare(baseline, actual)
                actual = initialize()
    except KeyboardInterrupt:
        sys.stdout.flush()

if __name__ == '__main__':
    main()
