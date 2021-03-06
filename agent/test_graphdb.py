import unittest
import graphdb

class TestGraphDB(unittest.TestCase):

    def test_add_vertex_ok(self):
        g = graphdb.graph([])
        v = g.add_vertex({'id': '123'})
        self.assertEqual('123', v.attributes['id'])
        
    def test_add_edge_ok(self):
        g = graphdb.graph([])
        a = g.add_vertex({})
        b = g.add_vertex({})
        e = g.add_edge(a, b)
        self.assertEqual(a, e.vertex_from)
        self.assertEqual(b, e.vertex_to)
        self.assertEqual(set([e]), a.edges_from)
        self.assertEqual(set([e]), b.edges_to)

    def test_update_attributes_ok(self):
        g = graphdb.graph(['id'])
        a = g.add_vertex({'id': '123'})
        g.update_attributes(a, {'id': '234'})
        s = g.find_vertices('id', '234')
        self.assertEqual(set([a]), s)

    def test_find_vertices_ok(self):
        g = graphdb.graph(['id'])
        a = g.add_vertex({'id': '123'})
        s = g.find_vertices('id', '123')
        self.assertEqual(set([a]), s)

    def test_merge_path_ok(self):
        g = graphdb.graph(['id'])
        a = g.add_vertex({'id': '1'})
        b = g.add_vertex({'id': '2'})
        g.add_edge(a, b)
        c = graphdb.vertex({'id': '2'})
        d = graphdb.vertex({'id': '3'})
        g.merge_path([c, d], 'id')
        self.assertEqual(3, len(g.vertices))
        self.assertEqual(2, len(g.edges))
        self.assertEqual(3, len(g.indexes['id']))

    def test_compare_ok(self):
        g = graphdb.graph(['id'])
        a = g.add_vertex({'id': '1'})
        b = g.add_vertex({'id': '2'})
        g.add_edge(a, b)
        g2 = graphdb.graph(['id'])
        c = g2.add_vertex({'id': '1'})
        d = g2.add_vertex({'id': '3'})
        e = g2.add_vertex({'id': '4'})
        g2.add_edge(c, d)
        p = g.compare(g2, 'id', lambda x: x == '4')
        self.assertEqual(2, len(p))
        self.assertIn([d], p)
        self.assertIn([c, d], p)

    def test_serialize__deserialize_ok(self):
        g = graphdb.graph(['id'])
        a = g.add_vertex({'id': '1'})
        b = g.add_vertex({'id': '2'})
        g.add_edge(a, b)
        s = graphdb.serialize(g)
        g2 = graphdb.deserialize(s)
        self.assertEqual(1, len(g2.indexes))
        self.assertEqual(2, len(g2.vertices))
        self.assertEqual(1, len(g2.edges))
        a2 = g2.find_vertices('id', '1').pop()
        b2 = g2.find_vertices('id', '2').pop()
        e2 = g2.edges.pop()
        self.assertEqual(a.attributes, a2.attributes)
        self.assertEqual(b.attributes, b2.attributes)
        self.assertEqual(a.attributes, e2.vertex_from.attributes)
        self.assertEqual(a.attributes, e2.vertex_from.attributes)
        
if __name__ == '__main__':
    unittest.main()
