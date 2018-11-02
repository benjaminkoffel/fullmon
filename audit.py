#!/usr/bin/env python3
import binascii
import codecs
import difflib
import os
import re
import socket
import struct
import time

re_auditd = re.compile('(?P<key>[\S]+)=(?P<value>"([^"]+)"|([\S]+))')
re_stat = re.compile('(\(\(([^\)]+)\)\)|\(([^\)]+)\)|([\S]+))')
re_container = re.compile('docker-containerd-shim.*([a-f0-9]{12})[a-f0-9]{52}.*')

def decode_saddr(saddr):
    c = codecs.decode(saddr, 'hex')
    p, i = struct.unpack_from("!H4s", c, offset=2)
    raw = codecs.decode(saddr, 'hex')
    family, = struct.unpack_from("@H", raw)
    if family == socket.AF_INET:
        port, ip = struct.unpack_from("!H4s", raw, offset=2)
        ip = socket.inet_ntoa(ip)
        return ip, port
    return None, None

def decode_proctitle(proctitle):
    try:
        return binascii.a2b_hex(proctitle).decode('utf-8').replace('\x00', ' ')
    except binascii.Error:
        return proctitle

def extract_container(cmd):
    m = re_container.match(cmd)
    return m.group(1) if m else ''

def to_netconn(messages):
    items = []
    syscall = [i for i in messages if i.get('type') == 'SYSCALL']
    proctitle = [i for i in messages if i.get('type') == 'PROCTITLE']
    sockaddr = [i for i in messages if i.get('type') == 'SOCKADDR']
    if syscall and proctitle and sockaddr:
        ip, port = decode_saddr(sockaddr[0]['saddr'])
        items.append({
            'type': 'netconn',
            'ppid': syscall[0]['ppid'],
            'pid': syscall[0]['pid'],
            'uid': syscall[0]['uid'],
            'exe': syscall[0]['exe'],
            'con': extract_container(decode_proctitle(proctitle[0]['proctitle'])),
            'ip': ip,
            'port': port
        })
    return items

def to_filemod(messages):
    items = []
    syscall = [i for i in messages if i.get('type') == 'SYSCALL']
    proctitle = [i for i in messages if i.get('type') == 'PROCTITLE']
    paths = [i for i in messages if i.get('type') == 'PATH']
    if syscall and proctitle and paths:
        values = []
        for path in paths:
            name, nametype = path.get('name'), path.get('nametype')
            if name and nametype in ['CREATE', 'DELETE']:
                items.append({
                    'type': 'filemod',
                    'ppid': syscall[0]['ppid'],
                    'pid': syscall[0]['pid'],
                    'uid': syscall[0]['uid'],
                    'exe': syscall[0]['exe'],
                    'con': extract_container(decode_proctitle(proctitle[0]['proctitle'])),
                    'path': name,
                    'action': nametype
                })  
    return items

def to_process(messages):
    items = []
    syscall = [i for i in messages if i.get('type') == 'SYSCALL']
    proctitle = [i for i in messages if i.get('type') == 'PROCTITLE']
    if syscall and proctitle:
        items.append({
            'type': 'process',
            'ppid': syscall[0]['ppid'],
            'pid': syscall[0]['pid'],
            'uid': syscall[0]['uid'],
            'exe': syscall[0]['exe'],
            'con': extract_container(decode_proctitle(proctitle[0]['proctitle']))
        })
    return items

def parse(line):
    values = {}
    for match in re_auditd.finditer(line):
        if match:
            values[match.group('key')] = match.group('value').strip('"')
    return values

def collect(line, action):
    if not hasattr(collect, 'buffer'):
        collect.buffer = []
    values = parse(line)
    if collect.buffer and collect.buffer[0]['msg'] != values.get('msg'):
        key = ''.join(i.get('key') for i in collect.buffer if i.get('type') == 'SYSCALL')
        if key == 'PROCESS':
            events = to_process(collect.buffer)
        elif key == 'FILEMOD':
            events = to_filemod(collect.buffer)
        elif key == 'NETCONN':
            events = to_netconn(collect.buffer)
        else:
            events = []
        action(events)
        collect.buffer = []
    collect.buffer.append(values)

def processes():
    items = []
    try:
        pids = [int(f) for f in os.listdir('/proc') if f.isdigit()]
    except FileNotFoundError:
        return items
    for pid in pids:
        try:
            with open('/proc/{}/stat'.format(pid)) as f:
                stat = f.read()
            with open('/proc/{}/uid_map'.format(pid)) as f:
                uid_map = f.read()
            with open('/proc/{}/cmdline'.format(pid)) as f:
                cmdline = f.read()
        except FileNotFoundError:
            continue # must exist
        try:
            exe = os.readlink('/proc/{}/exe'.format(pid))
        except FileNotFoundError:
            pass # may not exist
        stats = re_stat.findall(stat)
        ppid = int(stats[3][0])
        com = stats[1][0].strip('()').split('/')[0]
        uid = int(uid_map.split()[0])
        con = extract_container(cmdline)
        items.append({
            'type': 'process',
            'ppid': ppid,
            'pid': pid,
            'uid': uid,
            'exe': exe if exe else com,
            'con': con
        })
    return items

def identify_temps(filenames, min_similarity, min_found):
    def find_all(string, char):
        return [i for i, c in enumerate(string) if c == char]
    P = set()
    F = sorted(set(filenames))
    while F:
        f = F.pop()
        if '/' in f:
            S = [i for i in F if find_all(i, '/') == find_all(f, '/')]
            for s in S:
                m = difflib.SequenceMatcher(None, f, s).ratio()
                if m > min_similarity:
                    fp, sp = f.split('/'), s.split('/')
                    p = '/'.join(re.escape(sp[i]) if sp[i] == fp[i] else '[^/]+' for i in range(len(fp)))
                    L = [i for i in S if re.match(p, i)]
                    if len(L) > min_found:
                        for l in L:
                            F.remove(l)
                        P.add(p)
                        break
    return P
