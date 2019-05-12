import unittest
import graphdb

class TestGraphDB(unittest.TestCase):

    def test_append_proc(self):
        g, m = {}, {}
        e = [
            {
                'type': 'proc', 
                'ppid': 45, 
                'pid': 67, 
                'con': 'xyz', 
                'uid': 0, 
                'exe': 'bash'
            }
        ]
        graphdb.append(g, m, e)
        self.assertEqual(len(g), 2)
        self.assertEqual(g['p:45'], {'p:67'})
        self.assertEqual(g['p:67'], set())
        self.assertEqual(len(m), 2)
        self.assertEqual(m['p:45'], 'p:::')
        self.assertEqual(m['p:67'], 'p:xyz:0:bash')

    def test_append_filemod(self):
        g, m = {}, {}
        e = [
            {
                'type': 'filemod', 
                'ppid': 45, 
                'pid': 67, 
                'con': 'xyz', 
                'uid': 0, 
                'exe': 'bash',
                'action': 'CREATE',
                'path': '/root/blah'
            }
        ]
        graphdb.append(g, m, e)
        self.assertEqual(len(g), 3)
        self.assertEqual(g['p:45'], {'p:67'})
        self.assertEqual(g['p:67'], {'f:CREATE:/root/blah'})
        self.assertEqual(g['f:CREATE:/root/blah'], set())
        self.assertEqual(len(m), 3)
        self.assertEqual(m['p:45'], 'p:::')
        self.assertEqual(m['p:67'], 'p:xyz:0:bash')
        self.assertEqual(m['f:CREATE:/root/blah'], 'f:CREATE:/root/blah')
        
    def test_append_netconn(self):
        g, m = {}, {}
        e = [
            {
                'type': 'netconn', 
                'ppid': 45, 
                'pid': 67, 
                'con': 'xyz', 
                'uid': 0, 
                'exe': 'bash',
                'ip': '1.1.1.1',
                'port': '53'
            }
        ]
        graphdb.append(g, m, e)
        self.assertEqual(len(g), 3)
        self.assertEqual(g['p:45'], {'p:67'})
        self.assertEqual(g['p:67'], {'n:1.1.1.1:53'})
        self.assertEqual(g['n:1.1.1.1:53'], set())
        self.assertEqual(len(m), 3)
        self.assertEqual(m['p:45'], 'p:::')
        self.assertEqual(m['p:67'], 'p:xyz:0:bash')
        self.assertEqual(m['n:1.1.1.1:53'], 'n:1.1.1.1:53')

    def test_compress(self):
        g = {'p:45': {'p:67'}, 'p:67': {'f:CREATE:/root/blah'}, 'f:CREATE:/root/blah': set()}
        m = {'p:45': 'p:::', 'p:67': 'p:xyz:0:bash', 'f:CREATE:/root/blah': 'f:CREATE:/root/blah'}
        c = graphdb.compress(g, m)
        self.assertEqual(len(c), 3)
        self.assertEqual(c['p:::'], {'p:xyz:0:bash'})
        self.assertEqual(c['p:xyz:0:bash'], {'f:CREATE:/root/blah'})
        self.assertEqual(c['f:CREATE:/root/blah'], set())

    def test_compare_same(self):
        b = {'p:::': {'p:xyz:0:bash'}, 'p:xyz:0:bash': {'f:CREATE:/root/blah'}, 'f:CREATE:/root/blah': set()}
        c = {'p:::': {'p:xyz:0:bash'}, 'p:xyz:0:bash': {'f:CREATE:/root/blah'}, 'f:CREATE:/root/blah': set()}
        a = graphdb.compare(b, c, lambda x: False)
        self.assertEqual(a, [])
    
    def test_compare_diff(self):
        b = {'p:::': {'p:xyz:0:bash'}, 'p:xyz:0:bash': {'f:CREATE:/root/blah'}, 'f:CREATE:/root/blah': set()}
        c = {'p:xyz:0:bash': {'f:CREATE:/anomaly'}, 'f:CREATE:/anomaly': set()}
        a = graphdb.compare(b, c, lambda x: False)
        self.assertEqual(a, [['f:CREATE:/anomaly'], ['p:xyz:0:bash', 'f:CREATE:/anomaly']])

    def test_merge(self):
        b = {'p:::': {'p:xyz:0:bash'}, 'p:xyz:0:bash': set()}
        graphdb.merge(b, ['p:xyz:0:bash', 'f:CREATE:/root/blah'])
        self.assertEqual(b, {'p:::': {'p:xyz:0:bash'}, 'p:xyz:0:bash': {'f:CREATE:/root/blah'}, 'f:CREATE:/root/blah': set()})

if __name__ == '__main__':
    unittest.main()
