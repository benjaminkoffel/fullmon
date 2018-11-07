#!/usr/bin/env python3
import argparse
import datetime
import logging
import queue
import re
import sys
import threading
import time
import audit
import graphdb

logging.basicConfig(level=logging.INFO, format='%(asctime)s\t%(levelname)s\t%(message)s', stream=sys.stdout)

def record_events(graph, events):
    for event in events:
        if event['type'] in ['process', 'filemod', 'netconn']:
            A = graph.find_vertices('pid', event['ppid'])
            if not A:
                A = [graph.add_vertex({'pid': event['ppid'], 'id': 'proc:::'})]
            for a in A:
                id = 'proc:{}:{}:{}'.format(event['con'], event['uid'], event['exe'])
                B = graph.find_vertices('pid', event['pid'])
                if not B:
                    B = [graph.add_vertex({'pid': event['pid'], 'id': id})]
                for b in B:
                    if b.attributes['id'] != id:
                        graph.update_attributes(b, {'pid': event['pid'], 'id': id})
                    graph.add_edge(a, b, {})
                    logging.debug('+%s', id)
        if event['type'] == 'filemod':
            for a in graph.find_vertices('pid', event['pid']):
                id = 'file:{}:{}'.format(event['action'], event['path'])
                b = graph.add_vertex({'id': id})
                graph.add_edge(a, b, {})
                logging.debug('+%s', id)
        if event['type'] == 'netconn':
            for a in graph.find_vertices('pid', event['pid']):
                id = 'host:{}:{}'.format(event['ip'], event['port'])
                b = graph.add_vertex({'id': id})
                graph.add_edge(a, b, {})
                logging.debug('+%s', id)

def ignore_patterns(graph, min_similarity, min_found):
    patterns = set()
    filenames = [v.attributes['id'][12:] for v in graph.vertices if v.attributes['id'].startswith('file:')]
    for p in audit.identify_temps(filenames, min_similarity, min_found):
        logging.info('+ignore %s', p)
        patterns.add(re.compile('^file:[^:]+:{}$'.format(p)))
    return patterns

def monitor_queue(que, wait, graph):
    try:
        line = que.get(block=False)
        audit.collect(line, lambda x: record_events(graph, x))
        que.task_done()
    except queue.Empty:
        time.sleep(wait)

def initialize_graph():
    graph = graphdb.graph()
    graph.add_index('id')
    graph.add_index('pid')
    record_events(graph, audit.processes())
    return graph

def tail_file(path, wait, action):
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
        parser.add_argument('--rebase', action='store_true', help='Update baseline with detected behaviour anomalies.')
        args = parser.parse_args()
        # initialize state
        auditd_queue = queue.Queue()
        auditd_thread = threading.Thread(target=tail_file, args=(args.auditd, 0.1, lambda x: auditd_queue.put(x)))
        auditd_thread.daemon = True
        auditd_thread.start()
        ignore = set([re.compile('^proc:::$')])
        baseline, actual = initialize_graph(), graphdb.graph()
        state, init = 'baseline', datetime.datetime.now()
        logging.info(state)
        # event loop
        while True:
            try:
                now = datetime.datetime.now()
                # state transitions
                if state == 'baseline' and (now - init).seconds > args.baseline:
                    state, init = 'normalize', datetime.datetime.now()
                    logging.info(state)
                elif state == 'normalize':
                    state, init = 'prepare', datetime.datetime.now()
                    logging.info(state)
                elif state == 'prepare':
                    state, init = 'collect', datetime.datetime.now()
                    logging.info(state)
                elif state == 'collect' and (now - init).seconds > args.monitor:
                    state, init = 'detect', datetime.datetime.now()
                    logging.info(state)
                elif state == 'detect':
                    state, init = 'prepare', datetime.datetime.now()
                    logging.info(state)
                # perform work
                if state == 'baseline':
                    monitor_queue(auditd_queue, 0.1, baseline)
                elif state == 'normalize':
                    baseline = baseline.compress('id')
                    ignore = ignore.union(ignore_patterns(actual, 0.6, 3))
                elif state == 'prepare':
                    actual = initialize_graph()
                elif state == 'collect':
                    monitor_queue(auditd_queue, 0.1, actual)
                elif state == 'detect':
                    anomalies = baseline.compare(actual, 'id', lambda x: any(i for i in ignore if i.match(x)))
                    for path in anomalies:
                        logging.warning('->'.join(v.attributes['id'] for v in path))
                    if anomalies and args.rebase:
                        logging.debug('+rebase')
                        for path in anomalies:
                            baseline.merge_path(path, 'id')
                        ignore = ignore.union(ignore_patterns(actual, 0.6, 3))
            except Exception:
                logging.exception('event_loop')
    except Exception:
        logging.exception('main_func')
    except KeyboardInterrupt:
        sys.stdout.flush()

if __name__ == '__main__':
    main()
