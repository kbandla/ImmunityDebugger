#!/usr/bin/env python
"""
hook on bp strncpy(dest, src, size)
check if size == strlen(src) log callstack

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__ = '1.0'

import immlib
from immlib import LogBpHook
import immlib


class MyOwnHook(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)
        
    def run(self,regs):
        return
                
    def run2(self,regs):
        """This will be executed when hooktype happens"""
        imm = immlib.Debugger()
        imm.Error("hgook time")
        readaddr=""
        size=""
        src = regs['ESP'] + 0x8 #strncpy second arg
        maxlen = regs['ESP'] + 0xc #strncpy third arg
        res=imm.readMemory(src, 4)
        leng=imm.readMemory(maxlen,4)
        for a in res:
            readaddr="%s%s" % (a.encode('hex'),readaddr)
        readaddr="0x%s" %readaddr
        for a in leng:
            size="%s%s" % (a.encode('hex'),size)
        src_addr=int(readaddr,16)
        readed=""
        #read src arg
        readed=imm.readString(src_addr)
        imm.Log("strncpy source: %s" %readed)
        if len(readed) == int(size):
            imm.Log("*** STACK ***")
            callstack=imm.callStack()
            for a in callstack:
                imm.Log("Address: %08x - Stack: %08x - Procedure: %s - frame: %08x - called from: %08x" %( a.address,a.stack,a.procedure,a.frame,a.calledfrom))
        
        

def main(): 
    imm = immlib.Debugger()
    bp_address=0x77c47a90 # strncpy
    #bp_address=imm.setBreakpointOnName("strncpy")
    #77C47A90 strncpy                            8B4C24 0C        MOV ECX,DWORD PTR SS:[ESP+C]
    #imm.setWatchPoint(0x32772DDC) #change to your strncpy address
    
    logbp_hook = MyOwnHook()
    logbp_hook.add("bp_on_strncpy",bp_address)
    imm.Log("Placed strncpy hook: bp_on_strncpy")
    

            
            
        
if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"
    
                
        
    
    


        
   
    
    
    
    


    
    