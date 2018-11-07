import unittest
import audit

class TestAudit(unittest.TestCase):

    def test_decode_saddr_ok(self):
        saddr = '020000357F0000010000000000000000'
        ip, port = audit.decode_saddr(saddr)
        self.assertEqual('127.0.0.1', ip)
        self.assertEqual(53, port)

    def test_decode_proctitle_encoded_ok(self):
        proctitle = '7375646F00636174002F7661722F6C6F672F61756469742F61756469742E6C6F67'
        command = audit.decode_proctitle(proctitle)
        self.assertEqual('sudo cat /var/log/audit/audit.log', command)

    def test_decode_proctitle_unencoded_ok(self):
        proctitle = 'sudo cat /var/log/audit/audit.log'
        command = audit.decode_proctitle(proctitle)
        self.assertEqual('sudo cat /var/log/audit/audit.log', command)

    def test_extract_container_ok(self):
        command = 'docker-containerd-shim -namespace moby -workdir /var/lib/docker/165536.165536/containerd/daemon/io.containerd.runtime.v1.linux/moby/4f55ed852c01a9ba6a70f4a1b69c72bfdc9938f87fde0f17c914403f7147751a -address /var/run/docker/containerd/docker-containerd.sock -containerd-binary /usr/bin/docker-containerd -runtime-root /var/run/docker/runtime-runc'
        container = audit.extract_container(command)
        self.assertEqual('4f55ed852c01', container)

    def test_parse_ok(self):
        line = 'type=SYSCALL msg=audit(1541486490.851:193512): arch=c000003e syscall=59 success=yes exit=0 a0=23a8788 a1=255a408 a2=2631008 a3=59a items=2 ppid=2157 pid=17188 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="grep" exe="/bin/grep" key="PROCESS"'
        data = audit.parse(line)
        self.assertEqual('SYSCALL', data['type'])
        self.assertEqual('audit(1541486490.851:193512):', data['msg'])
        self.assertEqual('c000003e', data['arch'])
        self.assertEqual('59', data['syscall'])
        self.assertEqual('PROCESS', data['key'])

if __name__ == '__main__':
    unittest.main()
