# -*- coding: utf-8 -*-

import os
import networkx as nx
import sys
import json
import idaapi
import idautils
import idc
import math
from Constant import *
from data_process import *
from collections import defaultdict
from copy import deepcopy
from BBlock import BBlock
from bisect import bisect_right
# bin = idc.GetInputFile()
bin = idc.GetInputFilePath()
# basename = input_file_path[:-len(filename)]

# bin = sys.argv[0]

dirname = os.path.dirname(bin)
basename = os.path.basename(bin)

parameters_path = os.path.join(os.path.dirname(sys.argv[0]),"parameters.json")
parameters = json.load(open(parameters_path,"r"))


partition = parameters['partition']
attributes_num = parameters['attributes_num']

addr2funname = {}
funhash2name = {}
addr2node = {}
fun2bbs = defaultdict(list)

loc2functions = defaultdict(set)
loc2bbs = defaultdict(set)

min_addr = idc.get_inf_attr(INF_MIN_EA)
max_addr = idc.get_inf_attr(INF_MAX_EA)

CG = nx.DiGraph()

class BBWrapper(object):
  def __init__(self, ea, bb):
    self.ea_ = ea
    self.bb_ = bb

  def get_bb(self):
    return self.bb_

  def __lt__(self, other):
    return self.ea_ < other.ea_
class BBCache(object):
  def __init__(self):
    self.bb_cache_ = []
    for f in idautils.Functions():
        for bb in idaapi.FlowChart(idaapi.get_func(f),flags=idaapi.FC_PREDS):
            self.bb_cache_.append(BBWrapper(bb.startEA, bb))
    self.bb_cache_ = sorted(self.bb_cache_)

  def find_block(self, ea):
    i = bisect_right(self.bb_cache_, BBWrapper(ea, None))
    if i:
      return self.bb_cache_[i-1].get_bb()
    else:
      return None
bb_cache = BBCache()


def write_function_name_hash():
    output_name = dirname + os.sep + basename + "_hash2name.txt"
    with open(output_name,"w") as f:
        for hashval in funhash2name:
            f.write(str(hashval)+":"+funhash2name[hashval]+"\n")
    
    output_name = dirname + os.sep + basename + "_addr2name.txt"
    with open(output_name,"w") as f:
        for hashval in addr2funname:
            f.write(str(hashval)+":"+addr2funname[hashval]+"\n")

    output_name = dirname + os.sep + basename + "_fun2bbs.txt"
    with open(output_name,"w") as f:
        for hashval in fun2bbs:
            f.write(str(hashval)+":\n")
            for bb in fun2bbs[hashval]:
                f.write(str(bb[0])+":"+str(bb[1])+"\n")


def write_graph_txt(tail=""):
    global basename,dirname
    title = "function name,function name hash,addr,hashval,cmp_num,mem_num,ins_num,imme,offspring,betweeness"+"\n"
    f = open(dirname+os.sep+basename+"_graph"+tail+".txt","w")
    f.write(title)
    for node in CG.nodes():
        line = node.funName+","+str(node.funNameHash)+","+str(node.addr)+","+str(node.hashVal)+","+",".join([str(k) for k in node.get_attr()])+"\n"
        f.write(line)
    f.close()
def write_function2attributes(s="_function2attribute.json"):
    function2attributes = defaultdict(dict)
    for node in CG.nodes():
        function2attributes[node.funNameHash][node.hashVal]=node.get_attr()
    output_function2attributes = dirname + os.sep+ basename + s
    with open(output_function2attributes,"w") as ouf:
        json.dump(function2attributes,ouf)
def write_bb2attributes(s="_bb2attributes.json"):
    function2attributes = defaultdict(list)
    for node in CG.nodes():
        function2attributes[node.addr]=node.get_attr()
    output_function2attributes = dirname + os.sep+ basename + s
    with open(output_function2attributes,"w") as ouf:
        json.dump(function2attributes,ouf)
def write_bb2attributes_csv(s="_bb2attributes.csv"):
    global basename,dirname
    title = "function name,function name hash,addr,hashval,cmp_num,mem_num,ins_num,string_num,imme,offspring,betweeness"+"\n"
    f = open(dirname+os.sep+basename+s,"w")
    f.write(title)
    for node in CG.nodes():
        line = node.funName+","+str(node.funNameHash)+","+str(node.addr)+","+str(node.hashVal)+","+",".join([str(k) for k in node.get_attr()])+"\n"
        f.write(line)
    f.close()
def write_loc2functions(s="_loc2functions.json"):
    for loc in loc2functions:
        loc2functions[loc] = list(loc2functions[loc])
    output_loc2function = dirname + os.sep+ basename + s
    with open(output_loc2function,"w") as ouf:
        json.dump(loc2functions,ouf)
def write_loc2bbs(s="_loc2bbs.json"):
    for loc in loc2bbs:
        loc2bbs[loc] = list(loc2bbs[loc])
    output_loc2bbs = dirname + os.sep+ basename + s
    with open(output_loc2bbs,"w") as ouf:
        json.dump(loc2bbs,ouf)
def normalization_max_min_range(start=[0]*attributes_num,end=[100]*attributes_num):
    max_value = []
    min_value = []
    sum_value = []
    average_value = []
    number = len(CG.nodes())

    for i,node in enumerate(CG.nodes()):
        attrs = node.get_attr()
        if i==0:
            max_value = deepcopy(attrs)
            min_value = deepcopy(attrs)
            sum_value = deepcopy(attrs)
        else:
            for j,attr in enumerate(attrs):
                if attr > max_value[j]:
                    max_value[j] = attr
                if attr < min_value[j]:
                    min_value[j] = attr
                sum_value[j] = sum_value[j] + attr
    for p,value in enumerate(sum_value):
        average_value.append(value/(number+0.0))    

    for node in CG.nodes():
        attrs = node.get_attr()
        new_attrs = []
        for j,attr in enumerate(attrs):
            div = max_value[j]-min_value[j]
            if div==0:
                div = 1
            new_attrs.append(start[j]+(end[j]-start[j])*((attr-min_value[j])/(div)))
        node.set_attr_by_list(new_attrs)

def normalization_log():
    max_value = []
    min_value = []
    sum_value = []
    average_value = []
    number = len(CG.nodes())

    for i,node in enumerate(CG.nodes()):
        attrs = node.get_attr()
        if i==0:
            max_value = deepcopy(attrs)
            min_value = deepcopy(attrs)
            sum_value = deepcopy(attrs)
            min_value_without_zero = [1000000]*(len(max_value))
        else:
            for j,attr in enumerate(attrs):
                if attr > max_value[j]:
                    max_value[j] = attr
                if attr < min_value[j]:
                    min_value[j] = attr
                if attr < min_value_without_zero[j] and attr!=0 :
                    min_value_without_zero[j] = attr
                sum_value[j] = sum_value[j] + attr
    for p,value in enumerate(sum_value):
        average_value.append(value/(number+0.0))    

    record_min_value = [100]*len(list(CG.nodes())[0].get_attr())
    for node in CG.nodes():
        attrs = node.get_attr()
        new_attrs = []
        for j,attr in enumerate(attrs):
            if min_value_without_zero[j]<1:
                flag = -1
            else:
                flag = 1
            if attr!=0:
                put_value = flag*math.log(attr,min_value_without_zero[j])
                new_attrs.append(put_value)
                if put_value < record_min_value[j]: record_min_value[j]=put_value
            else:
                new_attrs.append(attr*flag)
        node.set_attr_by_list(new_attrs)
    for node in CG.nodes():
        attrs = node.get_attr()
        new_attrs = deepcopy(attrs)
        for j,attr in enumerate(attrs):
            if attr==0:
                new_attrs[j] = record_min_value[j]-0.001
        node.set_attr_by_list(new_attrs)

def pagerank(time=1):
    global CG,addr2node
    print(partition)
    for _ in range(time):
        new_CG = deepcopy(CG)
        new_addr2node = {}
        node2node = {}
        for node in new_CG.nodes():
            new_addr2node[node.addr] = node
        for addr in addr2node:
            node2node[addr2node[addr]]=new_addr2node[addr]
        for node in CG.nodes():
            in_degree = CG.in_degree(node)+0.0
            cur_attr = node.get_attr()
            if in_degree==0:
                continue
            else:
                pres = CG.predecessors(node)

                attributes = []
                for pre in pres:
                    out_degree = CG.out_degree(pre)+0.0
                    attr = pre.get_attr()
                    attributes.append(list_parameter_multiply(attr,1.0/out_degree))
                sum_of_attributes = sum_of_list_of_list(attributes)
                new_attributes1 = list_parameter_multiply(sum_of_attributes,1-partition)
                new_attributes1 = list_parameter_multiply(new_attributes1,1.0/(in_degree*in_degree))
                new_attributes2 = list_parameter_multiply(cur_attr,partition)
                new_attributes = list_add(new_attributes1,new_attributes2)
                node2node[node].set_attr_by_list(new_attributes)
        CG = new_CG
        addr2node = new_addr2node
def build_cg():
    global CG
    for f in idautils.Functions():
        flags = idc.GetFunctionAttr(f, FUNCATTR_FLAGS)
        function_name = GetFunctionName(f)
        refto = CodeRefsTo(f, 0)
        refto_len = CodeRefsTo(f, 0)
        cur_node = bb_cache.find_block(f)

        if refto_len==0:
            continue
        for ref_ea in refto:
            if not function_filter(ref_ea):
                continue
            prev_node = bb_cache.find_block(ref_ea)
            if flags & FUNC_LIB or flags & FUNC_THUNK:
                if prev_node.startEA in addr2node:
                    addr2node[prev_node.startEA].incre_mem_num()
            else:
                try:
                    CG.add_edge(addr2node[prev_node.startEA],addr2node[cur_node.startEA])
                except:
                    print(prev_node.startEA,prev_node.startEA in addr2node)
                    print(cur_node.startEA,cur_node.startEA in addr2node)
def set_attributes_betweenness_offspring():
    global CG
    print("nodes:%d"%(len(CG.nodes())))
    betweenness = nx.betweenness_centrality(CG,endpoints=True)
    print("got betweenness..")
    for key in addr2node:   
        node = addr2node[key]
        node.set_betweeness(betweenness[node])
        offspring=len(nx.descendants(CG,node))
        node.set_offspring(offspring)
        cmp_num = len(list(CG.successors(node)))
        node.set_cmp(cmp_num)
def get_node_object(block,fname,fnamehash):
    global addr2node
    mem_num = 0
    cmp_num = 0 
    ins_num = 0 
    imme_num = 0
    string_num = 0
    rv = -2 
    rv_shiift = -2 
    start,endEA = block.startEA, block.endEA
    cur_addr = start
    while cur_addr<endEA:
        if idc.get_operand_type(cur_addr, 0) == 5 and \
                (min_addr < idc.get_operand_value(cur_addr, 0) < max_addr):
            idc.OpOff(cur_addr, 0, 0)
        else:
            imme_num += 1
        if idc.get_operand_type(cur_addr, 1) == 5 and \
                (min_addr < idc.get_operand_value(cur_addr, 1) < max_addr):
            idc.op_plain_offset(cur_addr, 1, 0)
        else:
            imme_num += 1

        line = idc.generate_disasm_line(cur_addr,0)
        if "cs:__afl_area_ptr" in line:
            rv = -1
        elif rv==-1:
            rv = idc.get_operand_value(cur_addr, 1)
        if "movedwordptrfs:[rbx]" in line.replace(" ",""):
            rv_shiift = -1
        if rv_shiift==-1:
            rv_shiift = idc.get_operand_value(cur_addr, 1)
            if rv_shiift!=(rv>>1):
                print("XOR ERROR...")
                print(rv)
                print(rv>>1)
                print(rv_shiift)
                exit(1)
        menm = idc.GetMnem(cur_addr)
        ins_num += 1

        if menm in string_insn:
            string_num += 1
        cur_addr = idc.NextHead(cur_addr)
    fun2bbs[fnamehash].append((block.startEA,rv))
    cur_node = BBlock(rv,fname,fnamehash,block.startEA)
    cur_node.set_attr(cmp_num,mem_num,ins_num,string_num,imme_num,0.0,0.0)
    if block.startEA == 5640343:
        print("hello")
        exit(1)
    if rv!=-1:
        addr2node[block.startEA]=cur_node
    return cur_node
def get_nodes_from_one_function(f):
    global CG
    bbs = idaapi.FlowChart(idaapi.get_func(f),flags=idaapi.FC_PREDS)  
    bbs_num = len(list(idaapi.FlowChart(idaapi.get_func(f),flags=idaapi.FC_PREDS)))
    fname =  GetFunctionName(f)
    fnamehash = function_name_hash(fname)
    head = list(bbs)[0]
    if head.startEA in addr2node:
        head_node = addr2node[head.startEA]
    else:
        head_node = get_node_object(head,fname,fnamehash)
    if head_node.hashVal == -1:
        print("ERROR:head not hash...")
        exit(1)
    CG.add_node(head_node)
    avoid_cyc = []
    avoid_cyc.append(head.startEA)

    import sys
    if bbs_num > 970:
        sys.setrecursionlimit(bbs_num)

    for block in head.succs():
        get_nodes_from_one_function_helper(f,head_node,block,fname,fnamehash,avoid_cyc)
def get_nodes_from_one_function_helper(f,prev_node,cur,fname,fnamehash,avoid_cyc):
    global CG
    if cur.startEA in avoid_cyc:
        return
    avoid_cyc.append(cur.startEA)
    if cur.startEA in addr2node:
        cur_node = addr2node[cur.startEA]
    else:
        cur_node = get_node_object(cur,fname,fnamehash)
    if cur_node.hashVal != -1:
        CG.add_edge(prev_node,cur_node)
        if prev_node.hashVal != -1:
            loc = (prev_node.hashVal>>1)^(cur_node.hashVal)
            loc2bbs[loc].add(prev_node.hashVal)
            loc2bbs[loc].add(cur_node.hashVal)
            loc2functions[loc].add(fnamehash)
        elif len(prev_node.hashValList)>0:
            for hvl in prev_node.hashValList:
                loc = (hvl>>1)^(cur_node.hashVal)
                loc2bbs[loc].add(hvl)
                loc2bbs[loc].add(cur_node.hashVal)
                loc2functions[loc].add(fnamehash)
    else:
        if prev_node.hashVal != -1:
            cur_node.hashValList.append(prev_node.hashVal)
        else:
            cur_node.hashValList = deepcopy(prev_node.hashValList)

    for block in cur.succs():
        get_nodes_from_one_function_helper(f,cur_node,block,fname,fnamehash,avoid_cyc)
def function_filter(f):
    function_name = GetFunctionName(f)
    if "afl" in function_name or "__libc" in function_name:
        return False    
    flags = idc.GetFunctionAttr(f, FUNCATTR_FLAGS)
    if flags & FUNC_LIB or flags & FUNC_THUNK: 
        return False
    if idc.SegName(f)!=".text":
        return False
    return True

def get_data_feature():
    max_value = []
    min_value = []
    sum_value = []
    average_value = []
    square_average_value = [] 
    s_square = []
    square = []
    number = len(CG.nodes())

    for i,node in enumerate(CG.nodes()):
        attrs = node.get_attr()
        if i==0:
            max_value = deepcopy(attrs)
            min_value = deepcopy(attrs)
            sum_value = deepcopy(attrs)
            s_square = list_square(attrs)
        else:
            s_square = list_add(s_square,list_square(attrs))
            for j,attr in enumerate(attrs):
                if attr > max_value[j]:
                    max_value[j] = attr
                if attr < min_value[j]:
                    min_value[j] = attr
                sum_value[j] = sum_value[j] + attr
    for p,value in enumerate(sum_value):
        average_value.append(value/(number+0.0))  
        square_average_value.append(s_square[p]/(number+0.0))

    for p,value in enumerate(average_value):
        square.append(math.sqrt(square_average_value[p]-average_value[p]**2))


    print ("max:",max_value)
    print ("min:",min_value)
    print ("sum:",sum_value)
    print ("average:",average_value)
    print ("square",square)

    return {"mmax":max_value,"mmin":min_value,"ssum":sum_value,"aaverage":average_value,"ssquare":square}

def standardization(average_v,std_v):
    min_value = [1]*len(list(CG.nodes())[0].get_attr())
    for node in CG.nodes():
        attr = node.get_attr()
        new_attr = []
        for i,v in enumerate(attr):
            if v!=0:
                value = (v-average_v[i])/std_v[i]
                new_attr.append(value)
                if value < min_value[i]: min_value[i] = value
            else:
                new_attr.append(v)
        node.set_attr_by_list(new_attr)

def main_analysis():
    global bb_cache
    bb_cache = BBCache()
    funcs = idautils.Functions()
    for num,f in enumerate(funcs):
        fname = GetFunctionName(f)

        if not function_filter(f):
            continue
        fname = GetFunctionName(f)
        addr2funname[f] = fname
        funhash2name[function_name_hash(fname)]=fname
        get_nodes_from_one_function(f)

    print("[+]build cg...")
    build_cg()
    print("[+]set arrtributes of betweenness and offspring...")
    set_attributes_betweenness_offspring()

def main():
    main_analysis()
    write_graph_txt()
    write_function_name_hash()
    pagerank()
    data_feature = get_data_feature()
    standardization(data_feature["aaverage"],data_feature["ssquare"])
    normalization_max_min_range()
    normalization_log()
    normalization_max_min_range()
    write_bb2attributes()

    cg_pkl = os.path.join(dirname,basename+"_cg.pkl")
    
    nx.write_gpickle(CG,cg_pkl)

if __name__ == "__main__":
    q = None
    f = None
    partition = float(idc.ARGV[1])
    main()
    print("------------------------------------")

