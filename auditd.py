#!/usr/bin/env python3
import binascii
import codecs
import re
import socket
import struct

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
        return binascii.a2b_hex(proctitle).decode('ascii').replace('\x00', ' ')
    except binascii.Error:
        return proctitle

def to_netconn(messages):
    items = []
    syscall = [i for i in messages if i.get('type') == 'SYSCALL']
    sockaddr = [i for i in messages if i.get('type') == 'SOCKADDR']
    if syscall and sockaddr:
        ip, port = decode_saddr(sockaddr[0]['saddr'])
        items.append({
            'type': 'netconn',
            'ppid': syscall[0]['ppid'],
            'pid': syscall[0]['pid'],
            'exe': syscall[0]['exe'],
            'ip': ip,
            'port': port
        })
    return items

def to_filemod(messages):
    items = []
    syscall = [i for i in messages if i.get('type') == 'SYSCALL']
    paths = [i for i in messages if i.get('type') == 'PATH']
    if syscall and paths:
        values = []
        for path in paths:
            name, nametype = path.get('name'), path.get('nametype')
            if name and nametype in ['CREATE', 'DELETE']:
                items.append({
                    'type': 'filemod',
                    'ppid': syscall[0]['ppid'],
                    'pid': syscall[0]['pid'],
                    'exe': syscall[0]['exe'],
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
            # 'cmd': decode_proctitle(proctitle[0]['proctitle'])
        })
    return items

def parse(line):
    if not hasattr(parse, 'regex'):
        parse.regex = re.compile('(?P<key>[\S]+)=(?P<value>"([^"]+)"|([\S]+))')
    values = {}
    for match in parse.regex.finditer(line):
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
            action(to_process(collect.buffer))
        elif key == 'FILEMOD':
            action(to_filemod(collect.buffer))
        elif key == 'NETCONN':
            action(to_netconn(collect.buffer))
        collect.buffer = []
    collect.buffer.append(values)
