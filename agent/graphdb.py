#!/usr/bin/env python3
import collections

def append(graph, meta, events):
    for e in events:
        pp = 'p:{}'.format(e['ppid'])
        if pp not in graph:
            graph[pp] = set()
            if pp not in meta:
                meta[pp] = 'p:::'
        p = 'p:{}'.format(e['pid'])
        if p not in graph:
            graph[p] = set()
            meta[p] = 'p:{}:{}:{}'.format(e['con'], e['uid'], e['exe'])
        graph[pp].add(p)
        if e['type'] == 'filemod':
            f = 'f:{}:{}'.format(e['action'], e['path'])
            if f not in graph:
                graph[f] = set()
                meta[f] = f
            graph[p].add(f)
        if e['type'] == 'netconn':
            n = 'n:{}:{}'.format(e['ip'], e['port'])
            if n not in graph:
                graph[n] = set()
                meta[n] = n
            graph[p].add(n)

def compress(graph, meta):
    c = {v: set() for v in meta.values()}
    for a in graph:
        for b in graph[a]:
            if meta[a] in c:
                c[meta[a]].add(meta[b])
    return c

def compare(baseline, graph, ignore):
    a = []
    q = collections.deque([(v, []) for v in graph])
    while q:
        c, p = q.popleft()
        if ignore(c):
            continue
        if c not in baseline or (p and c not in baseline.get(p[-1], set())):
            a.append(p + [c])
        for n in graph[c] - set(p):
            q.append((n, p + [c]))
    return a

def merge(graph, path):
    p = None
    while path:
        c = path.pop()
        if c not in graph:
            graph[c] = set()
        if p:
            graph[c].add(p)
        p = c
