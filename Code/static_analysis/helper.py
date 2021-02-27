import os,sys

def exec_command_get_retval(command):
    result = os.popen(command)
    res = result.read()
    for line in res.splitlines():
        print(line)