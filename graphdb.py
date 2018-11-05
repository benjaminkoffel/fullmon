#!/usr/bin/env python3
import copy
import collections
import random

class vertex:

    def __init__(self, attributes):
        self.id = random.getrandbits(128)
        self.edges_from = set()
        self.edges_to = set()
        self.attributes = copy.deepcopy(attributes)

    def __hash__(self):
        return self.id
        
    def __eq__(self, other):
        return self.id == other.id

class edge:

    def __init__(self, vertex_from, vertex_to, attributes):
        self.id = random.getrandbits(128)
        self.vertex_from = vertex_from
        self.vertex_to = vertex_to
        self.vertex_from.edges_from.add(self)
        self.vertex_to.edges_to.add(self)
        self.attributes = copy.deepcopy(attributes)

    def __hash__(self):
        return self.id

    def __eq__(self, other):
        return self.id == other.id

class graph:

    def __init__(self):
        self.vertices = set()
        self.edges = set()
        self.indexes = {}

    def add_index(self, attribute):
        if attribute not in self.indexes:
            self.indexes[attribute] = {}
            for v in self.vertices:
                if attribute in v.attributes:
                    value = v.attributes[attribute]
                    if value not in self.indexes[attribute]:
                        self.indexes[attribute][value] = set([v])
                    else:
                        self.indexes[attribute][value].add(v)

    def add_vertex(self, attributes):
        v = vertex(attributes)
        self.vertices.add(v)
        for attribute in self.indexes.keys():
            if attribute in v.attributes:
                value = v.attributes[attribute]
                if value not in self.indexes[attribute]:
                    self.indexes[attribute][value] = set([v])
                else:
                    self.indexes[attribute][value].add(v)
        return v

    def update_attributes(self, vertex, attributes):
        for attribute in self.indexes.keys():
            if attribute in vertex.attributes:
                self.indexes[attribute][vertex.attributes[attribute]].remove(vertex)
        vertex.attributes = attributes
        for attribute in self.indexes.keys():
            if attribute in vertex.attributes:
                value = vertex.attributes[attribute]
                if value not in self.indexes[attribute]:
                    self.indexes[attribute][value] = set([vertex])
                else:
                    self.indexes[attribute][value].add(vertex)

    def add_edge(self, vertex_from, vertex_to, attributes):
        e = edge(vertex_from, vertex_to, attributes)
        self.edges.add(e)
        return e

    def find_vertices(self, attribute, value):
        if attribute not in self.indexes:
            return None
        if value not in self.indexes[attribute]:
            return set()
        return set(self.indexes[attribute][value])

    def list_leaf_paths(self):
        a = []
        q = collections.deque([(i, []) for i in self.vertices if not i.edges_to])
        while q:
            (v, p) = q.popleft()
            n = set(e.vertex_to for e in v.edges_from) - set(p)
            if not n:
                a.append(p + [v])
            else:
                for x in n:
                    q.append((x, p + [v]))
        return a

    def list_paths(self):
        a = []
        q = collections.deque([(i, []) for i in self.vertices])
        while q:
            (v, p) = q.popleft()
            a.append(p + [v])
            for n in set(e.vertex_to for e in v.edges_from) - set(p):
                q.append((n, p + [v]))
        return a

    def has_path(self, path, attribute):
        q = collections.deque([(i, []) for i in self.vertices])
        while q:
            (v, p) = q.popleft()
            if v.attributes[attribute] == path[len(p)].attributes[attribute]:
                if len(p) == len(path) - 1:
                    return True
                for n in set(e.vertex_to for e in v.edges_from):
                    q.append((n, p + [v]))
        return False

    def compress(self, attribute):
        g = graph()
        g.add_index(attribute)
        q = collections.deque([(i, [], None) for i in self.vertices])
        while q:
            (v, p, f) = q.popleft()
            S = g.find_vertices(attribute, v.attributes[attribute])
            if not S:
                S = set([g.add_vertex({attribute: v.attributes[attribute]})])
            s = S.pop()
            if f and not any(e for e in f.edges_from if e.vertex_to == s):
                g.add_edge(f, s, {})
            for n in set([e.vertex_to for e in v.edges_from]) - set(p):
                q.append((n, p + [v], s))
        return g
