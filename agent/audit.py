#!/usr/bin/env python3
import binascii
import codecs
import difflib
import os
import re
import socket
import struct

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

def process(messages):
    syscall = [i for i in messages if i.get('type') == 'SYSCALL']
    proctitle = [i for i in messages if i.get('type') == 'PROCTITLE']
    if syscall and proctitle:
        yield {
            'type': 'process',
            'ppid': syscall[0]['ppid'],
            'pid': syscall[0]['pid'],
            'uid': syscall[0]['auid'],
            'exe': syscall[0]['comm'],
            'con': extract_container(decode_proctitle(proctitle[0]['proctitle']))}

def filemod(messages):
    for proc in process(messages):
        for msg in messages:
            if msg.get('type') == 'PATH':
                name, nametype = msg['name'], msg['nametype']
                if nametype in ['CREATE', 'DELETE']:
                    yield {**proc, **{
                        'type': 'filemod',
                        'path': name,
                        'action': nametype}}

def netconn(messages):
    for proc in process(messages):
        for msg in messages:
            if msg.get('type') == 'SOCKADDR':
                ip, port = decode_saddr(msg['saddr'])
                yield {**proc, **{
                    'type': 'netconn',
                    'ip': ip,
                    'port': port}}

def parse(line):
    values = {}
    for match in re_auditd.finditer(line):
        if match:
            values[match.group('key')] = match.group('value').strip('"')
    return values

def tail(path, position):
    if not hasattr(tail, 'buffer'):
        tail.buffer = []
    events = []
    try:
        with open(path) as f:
            f.seek(0, 2)
            if f.tell() < position:
                f.seek(0, 0)
            else:
                f.seek(position, 0)
            for line in f:
                values = parse(line)
                if tail.buffer and tail.buffer[0]['msg'] != values.get('msg'):
                    key = ''.join(i.get('key') for i in tail.buffer if i.get('type') == 'SYSCALL')
                    if key == 'PROCESS':
                        events += process(tail.buffer)
                    elif key == 'FILEMOD':
                        events += filemod(tail.buffer)
                    elif key == 'NETCONN':
                        events += netconn(tail.buffer)
                    tail.buffer = []
                tail.buffer.append(values)
            position = f.tell()
    except IOError as e:
        pass
    return events, position

def processes():
    try:
        pids = [int(f) for f in os.listdir('/proc') if f.isdigit()]
    except FileNotFoundError:
        return
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
        stats = re_stat.findall(stat)
        ppid = int(stats[3][0])
        uid = int(uid_map.split()[0])
        exe = stats[1][0].strip('()').split('/')[0]
        con = extract_container(cmdline)
        yield {
            'type': 'process',
            'ppid': ppid,
            'pid': pid,
            'uid': uid,
            'exe': exe,
            'con': con}

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
