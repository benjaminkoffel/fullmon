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
                for n in set(e.vertex_to for e in v.edges_from) - set(p):
                    q.append((n, p + [v]))
        return False
