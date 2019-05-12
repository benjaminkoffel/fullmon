#!/usr/bin/env python3
import argparse
import datetime
import logging
import logging.handlers
import re
import sys
import time
import audit
import graphdb

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s\t%(levelname)s\t%(message)s', 
    handlers=[
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler('/var/log/fullmon.log', maxBytes=5242880, backupCount=20),
    ])

def update_ignore(ignore, min_similarity, min_found, graph):
    filenames = {v[9:] for v in graph if v.startswith('f:')}
    unignored = {f for f in filenames if not any(i for i in ignore if i.match(f))}
    for p in audit.identify_temps(unignored, min_similarity, min_found):
        logging.info('ignore %s', p)
        ignore.add(re.compile('^f:{}$'.format(p)))

def detect_anomalies(baseline, ignore, merge_enabled, alert_enabled, graph, meta):
    compressed = graphdb.compress(graph, meta)
    anomalies = graphdb.compare(baseline, compressed, lambda x: any(i for i in ignore if i.match(x)))
    if alert_enabled:
        for path in anomalies:
            logging.warning('->'.join(path))
    if merge_enabled:
        for path in anomalies:
            graphdb.merge(baseline, path)
        update_ignore(ignore, 0.5, 3, baseline)

def tail_auditd(auditd_path, monitor_seconds, wait_seconds, graph, meta):
    start = datetime.datetime.now()
    while (datetime.datetime.now() - start).seconds < monitor_seconds:
        graphdb.append(graph, meta, audit.tail(auditd_path))
        time.sleep(wait_seconds)

def monitor_loop(auditd_path, baseline_seconds, monitor_seconds, rebase_enabled, wait_seconds):
    logging.info('initialize')
    init = datetime.datetime.now()
    baseline = {}
    ignore = set([re.compile('^proc:::$')])
    while True:
        logging.info('monitor')
        graph, meta = {}, {}
        graphdb.append(graph, meta, audit.processes())
        tail_auditd(auditd_path, monitor_seconds, wait_seconds, graph, meta)
        alert_enabled = (datetime.datetime.now() - init).seconds > baseline_seconds
        merge_enabled = rebase_enabled or not alert_enabled
        logging.info('analyze')
        detect_anomalies(baseline, ignore, merge_enabled, alert_enabled, graph, meta)

def main():
    try:
        parser = argparse.ArgumentParser(description='Monitor auditd logs for anomalous user behaviour.')
        parser.add_argument('--auditd', help='Path to auditd log file.', default='/var/log/audit/audit.log')
        parser.add_argument('--baseline', type=float, help='Time in seconds to generate baseline.', default=3600)
        parser.add_argument('--monitor', type=float, help='Time in seconds before each baseline comparison.', default=60)
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
