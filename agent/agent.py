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

def update_ignore(ignore, min_similarity, min_found, graph):
    filenames = {
        v.attributes['id'][12:]
        for v in graph.vertices
        if v.attributes['id'].startswith('file:')
            and not any(i for i in ignore if i.match(v.attributes['id']))}
    for p in audit.identify_temps(filenames, min_similarity, min_found):
        logging.debug('+ignore %s', p)
        ignore.add(re.compile('^file:[^:]+:{}$'.format(p)))

def detect_anomalies(current, baseline, ignore, merge_enabled, alert_enabled):
    anomalies = baseline.compare(current, 'id', lambda x: any(i for i in ignore if i.match(x)))
    if alert_enabled:
        for path in anomalies:
            logging.warning('->'.join(v.attributes['id'] for v in path))
    if merge_enabled:
        for path in anomalies:
            baseline.merge_path(path, 'id')
        update_ignore(ignore, 0.5, 3, baseline)

def tail_auditd(auditd_path, monitor_seconds, wait_seconds, graph):
    start = datetime.datetime.now()
    while (datetime.datetime.now() - start).seconds < monitor_seconds:
        record_events(graph, audit.tail(auditd_path))
        time.sleep(wait_seconds)

def initialize_graph():
    graph = graphdb.graph(['pid', 'id'])
    record_events(graph, audit.processes())
    return graph

def monitor_loop(auditd_path, baseline_seconds, monitor_seconds, rebase_enabled, wait_seconds):
    logging.info('initialize')
    init = datetime.datetime.now()
    baseline = graphdb.graph(['id'])
    ignore = set([re.compile('^proc:::$')])
    while True:
        logging.info('monitor')
        current = initialize_graph()
        tail_auditd(auditd_path, monitor_seconds, wait_seconds, current)
        alert_enabled = (datetime.datetime.now() - init).seconds > baseline_seconds
        merge_enabled = rebase_enabled or not alert_enabled
        logging.info('analyze')
        detect_anomalies(current, baseline, ignore, merge_enabled, alert_enabled)

def main():
    try:
        parser = argparse.ArgumentParser(description='Monitor auditd logs for anomalous user behaviour.')
        parser.add_argument('--auditd', help='Path to auditd log file.', required=True)
        parser.add_argument('--baseline', type=float, help='Time in seconds to generate baseline.', required=True)
        parser.add_argument('--monitor', type=float, help='Time in seconds before each baseline comparison.', required=True)
        parser.add_argument('--rebase', action='store_true', help='Update baseline with detected behaviour anomalies.')
        parser.add_argument('--wait', type=float, help='Time in seconds to wait between auditd log reads.', default=0.5)
        args = parser.parse_args()
        monitor_loop(args.auditd, args.baseline, args.monitor, args.rebase, args.wait)
    except Exception:
        logging.exception('main')
    except KeyboardInterrupt:
        sys.stdout.flush()

if __name__ == '__main__':
    main()
