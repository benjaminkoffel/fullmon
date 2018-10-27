#!/usr/bin/env python3
import argparse
import datetime
import logging
import queue
import sys
import threading
import time
import audit
import graphdb

logging.basicConfig(level=logging.INFO, format='%(asctime)s\t%(levelname)s\t%(message)s', stream=sys.stdout)

def compare(baseline, actual):
    paths = actual.list_paths()
    for path in paths:
        pruned = [p for p in path if p.attributes['id'] != 'proc::']
        if len(pruned) > 1:
            logging.debug('+compare')
            if not baseline.has_path(pruned, 'id'):
                logging.warning('->'.join(v.attributes['id'] for v in pruned))

def record(graph, events):
    for event in events:
        if event['type'] in ['process', 'filemod', 'netconn']:
            A = graph.find_vertices('process.pid', event['ppid'])
            if not A:
                A = [graph.add_vertex({
                    'id': 'proc::',
                    'process.pid': event['ppid']})]
            for a in A:
                B = graph.find_vertices('process.pid', event['pid'])
                if not B:
                    B = [graph.add_vertex({
                        'id': 'proc:{}:{}'.format(event['uid'], event['exe']),
                        'process.pid': event['pid']})]
                for b in B:
                    b.attributes['uid'] = event['uid']
                    b.attributes['exe'] = event['exe']
                    graph.add_edge(a, b, {})
                    logging.debug('+exec %s %s %s', event['pid'], event['uid'], event['exe'])
        if event['type'] == 'filemod':
            for a in graph.find_vertices('process.pid', event['pid']):
                b = graph.add_vertex({
                    'id': 'file:{}:{}'.format(event['action'], event['path'])})
                graph.add_edge(a, b, {})
                logging.debug('+filemod %s %s %s', event['pid'], event['action'], event['path'])
        if event['type'] == 'netconn':
            for a in graph.find_vertices('process.pid', event['pid']):
                b = graph.add_vertex({
                    'id': 'host:{}:{}'.format(event['ip'], event['port'])})
                graph.add_edge(a, b, {})
                logging.debug('+netconn %s %s %s', event['pid'], event['ip'], event['port'])

def initialize_graph():
    graph = graphdb.graph()
    graph.add_index('id')
    graph.add_index('process.pid')
    record(graph, audit.processes())    
    return graph

def tail(path, wait, action):
    cur = 0
    while True:
        try:
            with open(path) as f:
                f.seek(0,2)
                if f.tell() < cur:
                    f.seek(0,0)
                else:
                    f.seek(cur,0)
                for line in f:
                    action(line)
                cur = f.tell()
        except IOError as e:
            pass
        except Exception:
            logging.exception('tail_loop')
        time.sleep(wait)

def main():
    try:
        # define parameters
        parser = argparse.ArgumentParser(description='Monitor auditd logs for anomalous user behaviour.')
        parser.add_argument('--auditd', help='Path to auditd log file.', required=True)
        parser.add_argument('--baseline', type=int, help='Time in seconds to generate baseline.', required=True)
        parser.add_argument('--monitor', type=int, help='Time in seconds before each baseline comparison.', required=True)
        args = parser.parse_args()
        # initialize state
        wait_seconds = 0.1
        auditd_queue = queue.Queue()
        auditd_thread = threading.Thread(target=tail, args=(args.auditd, wait_seconds, lambda x: auditd_queue.put(x)))
        auditd_thread.daemon = True
        auditd_thread.start()
        baseline, actual = initialize_graph(), initialize_graph()
        state, init = 'baseline', datetime.datetime.now()
        logging.info(state)
        # event loop
        while True:
            try:
                now = datetime.datetime.now()
                # state transitions
                if state == 'baseline' and (now - init).seconds > args.baseline:
                    state, init = 'collect', datetime.datetime.now()
                    logging.info(state)
                elif state == 'collect' and (now - init).seconds > args.monitor:
                    state, init = 'detect', datetime.datetime.now()
                    logging.info(state)
                elif state == 'detect':
                    state, init = 'collect', datetime.datetime.now()
                    logging.info(state)
                # perform work
                if state == 'baseline':
                    try:
                        line = auditd_queue.get(block=False)
                        audit.collect(line, lambda x: record(baseline, x))
                        auditd_queue.task_done()
                    except queue.Empty:
                        time.sleep(wait_seconds)
                elif state == 'collect':
                    try:
                        line = auditd_queue.get(block=False)
                        if line:
                            audit.collect(line, lambda x: record(actual, x))
                            auditd_queue.task_done()
                    except queue.Empty:
                        time.sleep(wait_seconds)
                elif state == 'detect':
                    compare(baseline, actual)
                    actual = initialize_graph()
            except Exception:
                logging.exception('event_loop')
    except Exception:
        logging.exception('main_func')
    except KeyboardInterrupt:
        sys.stdout.flush()

if __name__ == '__main__':
    main()
