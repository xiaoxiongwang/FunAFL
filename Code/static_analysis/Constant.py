# -*- coding: utf-8 -*-
cmp_insn = ["jmp","cmp","test","jz","jnz","jc","jnc","je","jne",\
    "js","jns","jo","jno","jp","jpe","jnp","jpo","ja","hnbe",
    "jae","jnb","jb","jane","jbe","jna","jg","jnle",\
        "jge","jnl","jl","jnge","jle","jng","cmp","cmpsb","cmpsw","cmpsd","cmpxchg","cmpxchg"]
mem_insn = ["malloc","calloc","realloc","alloca","free","shmat",\
    "fopen","fread","fputc","memcpy","memcmp","read","write","memset","strtod"]
string_insn = ["cmps", "cmpsq", "cmpsb", "cmpsd", "cmpsl", "cmpsw", "lods","lodsq", \
    "lodsb", "lodsl", "lodsd", "lodsw", "movs", "movsq","movsb", "movsl", "movsd", \
        "smovl", "movsw", "smovw", "scas","scasq", "scasb", "scasl", "scasd", \
            "scasw", "stos", "stosq","stosb", "stosl", "stosd", "stosw","rep", "repe", "repz", "repne", "repnz"]