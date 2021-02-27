
# -*- coding: utf-8 -*-
from copy import deepcopy

def function_name_hash(fname):
    seed = 31
    hashVal = 0
    for i in fname:
        hashVal = hashVal * seed +ord(i)
    return (hashVal & 0x7FFFFFFF)

def list_square(l):
    result = []
    for key in l:
        result.append(key*key)
    return result
def list_add(list1,list2):
    if len(list1)==0:
        return deepcopy(list2)
    if len(list2)==0:
        return deepcopy(list1)
    assert len(list1)==len(list2)        
    list_sum = []
    for i in range(len(list1)):
        list_sum.append(list1[i]+list2[i])
    return list_sum

def list_parameter_multiply(list1,a):
    list2 = []
    for i in list1:
        list2.append(a*i)
    return list2

def sum_of_list_of_list(list_of_list):
    sum = []
    for m in list_of_list:
        sum = list_add(sum,m)
    return sum