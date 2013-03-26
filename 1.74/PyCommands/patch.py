#!/usr/bin/env python
"""
Immunity Debugger Patcher

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""

__VERSION__ = '1.1'

NOTES="""
anti-antidebugging is here

DONE: IsDebuggerPresent
TODO:
* EnumProcesses
* CreateToolhelp32Snapshot, Process32First, Process32Next, 
* UnhandeldExceptionFilter - ZwQueryInformationProcess
* ProcessHeapFlag  &  NTGlobalFlag
"""

import immlib
from immlib import BpHook
import getopt

DESC="Patches anti-debugging protection  ,  [-t TYPE_OF_PROTECTION]"

def usage(imm):
    imm.log("!patch -t TYPE",focus=1)
    
def main(args):
    types={"isdebuggerpresent": 0}
    imm = immlib.Debugger()
    
    if not args:
        return "give patch type..."
    
    
    try:
        opts, argo = getopt.getopt(args, "t:s")
    except getopt.GetoptError:
        usage(imm)
        return "Bad patch argument %s" % args[0]
    
    type = None

    for o,a in opts:
        if o == '-t':
            low = a.lower()
            if types.has_key( low ):
                type = types[ low ]
            else:
                return "Invalid type: %s" % a
        

    # IsDebuggerPresent
    if type == 0:
        imm.log( "Patching IsDebuggerPresent..." )
        ispresent = imm.getAddress( "kernel32.IsDebuggerPresent" )
        imm.writeMemory( ispresent, imm.assemble( "xor eax, eax\n ret" ) )
                        
        return "IsDebuggerPresent patched"
    
    else:
        usage(imm)
        return "Bad patch argument"
        