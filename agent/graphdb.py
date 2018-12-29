#!/usr/bin/env python3
import copy
import collections
import json
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

    def __init__(self, vertex_from, vertex_to):
        self.id = random.getrandbits(128)
        self.vertex_from = vertex_from
        self.vertex_to = vertex_to
        self.vertex_from.edges_from.add(self)
        self.vertex_to.edges_to.add(self)

    def __hash__(self):
        return self.id

    def __eq__(self, other):
        return self.id == other.id

class graph:

    def __init__(self, attributes):
        self.vertices = set()
        self.edges = set()
        self.indexes = {a: {} for a in attributes}

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

    def add_edge(self, vertex_from, vertex_to):
        e = edge(vertex_from, vertex_to)
        self.edges.add(e)
        return e

    def find_vertices(self, attribute, value):
        if attribute not in self.indexes:
            return None
        if value not in self.indexes[attribute]:
            return set()
        return set(self.indexes[attribute][value])

    def merge_path(self, path, attribute):
        f = None
        q = collections.deque(path)
        while q:
            v = q.popleft()
            S = self.find_vertices(attribute, v.attributes[attribute])
            if not S:
                S = set([self.add_vertex({attribute: v.attributes[attribute]})])
            s = S.pop()
            if f and not any(e for e in f.edges_from if e.vertex_to == s):
                self.add_edge(f, s)
            f = s

    def compare(self, other, attribute, ignore):
        a = []
        q = collections.deque([(i, []) for i in other.vertices])
        while q:
            (v, p) = q.popleft()
            if ignore(v.attributes[attribute]):
                continue
            S = self.find_vertices(attribute, v.attributes[attribute])
            if not S or (p and not any(e for e in S.pop().edges_to if e.vertex_from.attributes[attribute] == p[-1].attributes[attribute])):
                a.append(p + [v])
            for n in set(e.vertex_to for e in v.edges_from) - set(p):
                q.append((n, p + [v]))
        return a

def serialize(obj):
    return json.dumps({
        'indexes': [i for i in obj.indexes],
        'vertices': {v.id: v.attributes for v in obj.vertices},
        'edges': {e.vertex_from.id: e.vertex_to.id for e in obj.edges}
    })

def deserialize(text):
    data = json.loads(text)
    obj = graph(data['indexes'])
    lookup = {}
    for i, a in data['vertices'].items():
        lookup[str(i)] = obj.add_vertex(a)
    for f, t in data['edges'].items():
        obj.add_edge(lookup[str(f)], lookup[str(t)])
    return obj
