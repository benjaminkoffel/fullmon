#!/usr/bin/env python3
import argparse
import datetime
import logging
import re
import sys
import time
import audit
import graphdb

logging.basicConfig(level=logging.INFO, format='%(asctime)s\t%(levelname)s\t%(message)s', stream=sys.stdout)

# todo: temp file pattern detection requires optimization or refactoring
def ignore_patterns(graph, min_similarity, min_found):
    patterns = set()
    filenames = {v.attributes['id'][12:] for v in graph.vertices if v.attributes['id'].startswith('file:')}
    for p in audit.identify_temps(filenames, min_similarity, min_found):
        logging.debug('+ignore %s', p)
        patterns.add(re.compile('^file:[^:]+:{}$'.format(p)))
    return patterns

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

def event_loop(auditd_path, baseline_seconds, monitor_seconds, rebase_enabled, wait_seconds):
    logging.info('initialize')
    ignore = set([re.compile('^proc:::$')])
    baseline = graphdb.graph(['id'])
    current = graphdb.graph(['pid', 'id'])
    record_events(current, audit.processes())
    position = 0
    init, start = datetime.datetime.now(), datetime.datetime.now()
    logging.info('monitor')
    while True:
        now = datetime.datetime.now()
        events, position = audit.tail(auditd_path, position)
        record_events(current, events)
        if (now - start).seconds > monitor_seconds:
            anomalies = baseline.compare(current, 'id', lambda x: any(i for i in ignore if i.match(x)))
            for path in anomalies:
                if rebase_enabled or (now - init).seconds <= baseline_seconds:
                    baseline.merge_path(path, 'id')
                if (now - init).seconds > baseline_seconds:
                    logging.warning('->'.join(v.attributes['id'] for v in path))
            ignore = ignore.union(ignore_patterns(baseline, 0.5, 3))
            current = graphdb.graph(['pid', 'id'])
            record_events(current, audit.processes())
            start = datetime.datetime.now()
            logging.info('monitor')
        time.sleep(wait_seconds)

def main():
    try:
        # define parameters
        parser = argparse.ArgumentParser(description='Monitor auditd logs for anomalous user behaviour.')
        parser.add_argument('--auditd', help='Path to auditd log file.', required=True)
        parser.add_argument('--baseline', type=int, help='Time in seconds to generate baseline.', required=True)
        parser.add_argument('--monitor', type=int, help='Time in seconds before each baseline comparison.', required=True)
        parser.add_argument('--rebase', action='store_true', help='Update baseline with detected behaviour anomalies.')
        args = parser.parse_args()
        event_loop(args.auditd, args.baseline, args.monitor, args.rebase, 0.5)        
    except Exception:
        logging.exception('main')
    except KeyboardInterrupt:
        sys.stdout.flush()

if __name__ == '__main__':
    main()
