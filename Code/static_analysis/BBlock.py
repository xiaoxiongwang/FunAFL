class BBlock(object):
    def __init__(self,hashVal,funName,funNameHash,addr):
        self.hashVal = hashVal
        self.hashValList = []
        self.funName = funName
        self.funNameHash = funNameHash
        self.addr = addr
        self.cmp_num = 0
        self.string_num = 0 
        self.imme = 0
        self.mem_num = 0
        self.ins_num = 0
        self.offspring = 0.0
        self.betweeness = 0.0

    def set_attr(self,cmp_num,mem_num,ins_num,string_num,imme,offspring,betweeness):
        self.cmp_num = cmp_num
        self.mem_num = mem_num
        self.ins_num = ins_num
        self.offspring = offspring
        self.betweeness = betweeness
        self.imme = imme
        self.string_num = string_num
    def set_attr_by_list(self,list_attr):
        self.cmp_num = list_attr[0]
        self.mem_num = list_attr[1]
        self.ins_num = list_attr[2]
        self.string_num = list_attr[3]
        self.imme = list_attr[4]
        self.offspring = list_attr[5]
        self.betweeness = list_attr[6]
    def add_attr_by_list(self,list_attr):
        self.cmp_num += list_attr[0]
        self.mem_num += list_attr[1]
        self.ins_num += list_attr[2]
        self.string_num += list_attr[3]
        self.imme += list_attr[4]
        self.offspring += list_attr[5]
        self.betweeness += list_attr[6]
    def get_attr(self):
        return [self.cmp_num,self.mem_num,self.ins_num,self.string_num,self.imme,self.offspring,self.betweeness]
    def set_betweeness(self,betweeness):
        self.betweeness = betweeness
    def set_offspring(self,offspring):
        self.offspring = offspring
    def set_imme(self,imme):
        self.imme = imme
    def set_cmp(self,cmp_num):
        self.cmp_num = cmp_num
    def incre_mem_num(self):
        self.mem_num = self.mem_num + 1
