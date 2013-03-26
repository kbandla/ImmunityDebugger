"""
Immunity Debugger Regexp Search

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

search.py - simple script that lets you quickie search for regexp
"""

__VERSION__ = '1.1'


import immlib

# TODO: -a <ASM> -m <modname>, search all on no -m
# TODO: migrate/replace searchcode.py

DESC = "Search for given assembly code"

def usage(imm):
    imm.log("!search <ASM>")
    imm.log("For example: !search pop r32\\npop r32\\nret")

def main(args):
    if not args:
        return "Usage: !search <ASM>"
    imm = immlib.Debugger()
    code = " ".join(args).replace("\\n","\n")
    ret = imm.searchCommands(code.upper())
    for a in ret:
        result=imm.disasm(a[0])
        imm.log("Found %s at 0x%X (%s)"% (result.result, a[0], a[2]), address=a[0],  focus=1)
    return "Search completed!"

