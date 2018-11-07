import unittest
import graphdb

class TestGraphDB(unittest.TestCase):

    def test_add_index_ok(self):
        g = graphdb.graph()
        i = g.add_index('id')
        self.assertEqual({}, i)

    def test_add_vertex_ok(self):
        g = graphdb.graph()
        v = g.add_vertex({'id': '123'})
        self.assertEqual('123', v.attributes['id'])
        
    def test_add_edge_ok(self):
        g = graphdb.graph()
        a = g.add_vertex({})
        b = g.add_vertex({})
        e = g.add_edge(a, b, {'id': '123'})
        self.assertEqual('123', e.attributes['id'])
        self.assertEqual(a, e.vertex_from)
        self.assertEqual(b, e.vertex_to)
        self.assertEqual(set([e]), a.edges_from)
        self.assertEqual(set([e]), b.edges_to)

    def test_update_attributes_ok(self):
        g = graphdb.graph()
        g.add_index('id')
        a = g.add_vertex({'id': '123'})
        g.update_attributes(a, {'id': '234'})
        s = g.find_vertices('id', '234')
        self.assertEqual(set([a]), s)

    def test_find_vertices_ok(self):
        g = graphdb.graph()
        g.add_index('id')
        a = g.add_vertex({'id': '123'})
        s = g.find_vertices('id', '123')
        self.assertEqual(set([a]), s)

    def test_compress_ok(self):
        g = graphdb.graph()
        g.add_index('id')
        a = g.add_vertex({'id': '1'})
        b = g.add_vertex({'id': '1'})
        c = g.add_vertex({'id': '2'})
        g.add_edge(a, b, {})
        g.add_edge(b, c, {})
        g2 = g.compress('id')
        self.assertEqual(2, len(g2.vertices))
        self.assertEqual(2, len(g2.edges))
        self.assertEqual(2, len(g2.indexes['id']))

    def test_merge_path_ok(self):
        g = graphdb.graph()
        g.add_index('id')
        a = g.add_vertex({'id': '1'})
        b = g.add_vertex({'id': '2'})
        g.add_edge(a, b, {})
        c = graphdb.vertex({'id': '2'})
        d = graphdb.vertex({'id': '3'})
        g.merge_path([c, d], 'id')
        self.assertEqual(3, len(g.vertices))
        self.assertEqual(2, len(g.edges))
        self.assertEqual(3, len(g.indexes['id']))

    def test_compare_ok(self):
        g = graphdb.graph()
        g.add_index('id')
        a = g.add_vertex({'id': '1'})
        b = g.add_vertex({'id': '2'})
        g.add_edge(a, b, {})
        g2 = graphdb.graph()
        g2.add_index('id')
        c = g2.add_vertex({'id': '1'})
        d = g2.add_vertex({'id': '3'})
        e = g2.add_vertex({'id': '4'})
        g2.add_edge(c, d, {})
        p = g.compare(g2, 'id', lambda x: x == '4')
        self.assertEqual(2, len(p))
        self.assertIn([d], p)
        self.assertIn([c, d], p)
        
if __name__ == '__main__':
    unittest.main()
