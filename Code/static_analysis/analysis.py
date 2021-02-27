import pickle
import os
import networkx as nx

def find_node_by_name(name,graph):
    for node in graph.nodes():
        if node.funName == name: 
            print(node.addr)
            return node
    print("Not Found!")

def find_node_by_addr(addr,graph):
    for node in graph.nodes():
        if node.addr == addr: 
            print(node,node.funName)
            return node
    print("Not Found!")


def find_head_of_function(addr,graph):
    for node in graph.nodes():
        if node.addr == addr: 
            print(node)
            return node
    print("Not Found!")