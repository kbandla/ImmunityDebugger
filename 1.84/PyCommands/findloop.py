"""
(c) Immunity, Inc. 2004-2008


U{Immunity Inc.<http://www.immunityinc.com>}

findloop

"""


from immlib import *
from immutils import *
import getopt

DESC=""" Find natural loops given a function start address """

def usage(imm):
    imm.log("!findloop -a <address>")
    imm.log("-a (function start address)")
    imm.log("-h This help")

def main(args):
    imm = Debugger()
    try:
        opts,argo = getopt.getopt(args, "a:")
    except:
        return usage(imm)
    for o,a in opts:
        if o == "-a":
            loops = imm.findLoops(int(a,16))
            for loop in loops:
                imm.log("LOOP! from:0x%08x, to:0x%08x"%(loop[0],loop[1]),loop[0])
                
                func = imm.getFunction(int(a,16))
                bbs = func.getBasicBlocks()
                
                #find first and last node
                first = 0xffffffff
                last = 0
                for node in loop[2]:
                    if node < first: first = node
                    if node > last: last = node
                
                #mark loop nodes, but NOT change anything if there's any kind of comment
                for node in loop[2]:
                    imm.log("    Loop node:0x%08x"%node,node)
                    for bb in bbs:
                        if bb.getStart() == node:
                            instrs = bb.getInstructions(imm)
                            for op in instrs:
                                if not imm.getComment(op.getAddress()) and op.getAddress() != node:
                                    if node == last and op.getAddress() == instrs[-1].getAddress():
                                        #last instruction of last node
                                        imm.setComment(op.getAddress(), "/")
                                    else:
                                        imm.setComment(op.getAddress(), "|")

                    if not imm.getComment(node):
                        if node == first:
                            imm.setComment(node, "\ Loop 0x%08X Node"%(loop[0]))
                        else:
                            imm.setComment(node, "| Loop 0x%08X Node"%(loop[0]))
                                    
            return "Done!"
        if o =="-h":
            return usage(imm)
