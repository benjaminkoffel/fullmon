#!/usr/bin/env python3 
import codecs, struct, socket, sys
 
def decode(saddr):
    c = codecs.decode(saddr, 'hex')
    p, i = struct.unpack_from("!H4s", c, offset=2)
    raw = codecs.decode(saddr, 'hex')
    family, = struct.unpack_from("@H", raw)
    print('family:', family)
    if family == socket.AF_INET:
        port, ip = struct.unpack_from("!H4s", raw, offset=2)
        ip = socket.inet_ntoa(ip)
        return port, ip
    elif family == socket.AF_UNIX:
        fname = raw[2:]
        return fname

print(decode(sys.argv[1].strip()))
