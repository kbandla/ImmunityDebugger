#!/usr/bin/env python
"""
basic block example

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__ = '1.0'

import immlib

def main(): 
    imm = immlib.Debugger()
    imm.markBegin()
    func_list = imm.getAllFunctions(0x00400000)
    imm.Error("%s" % str(func_list))
    i=0
    for f in func_list:
        i=1+i
        #if i > 4: # show first 4 functs
            #break
        function=imm.getFunction(f)
        basicblocks = function.getBasicBlocks()
        for bb in basicblocks:
            imm.log("    BB start: %x - end %x" % (bb.start,bb.end))
            inst_set=bb.getInstructions(imm)
            for inst in inst_set:
                imm.Log("        Inst: %s" % inst.result)
    totaltime=imm.markEnd()
    imm.log("Used time: %d seconds" % totaltime)
    

if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"
                
            
        
    