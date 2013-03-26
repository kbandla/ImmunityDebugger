#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""

import immlib
import getopt


__VERSION__ = '1.1'

DESC= "Static Analysis: Mark the tiny ones" 

def usage(imm):
    """ All the options"""
    imm.Log("!mark  search and mark given function")
    imm.Log("!mark [-f NAME ] [-c COMMENT] [-m MODULE]")
    imm.Log("Example: mark with DANGER_MOUSE string all the strcpy ones")
    imm.Log("!mark -f strcpy -c DANGER_MOUSE -m ALL")
    
    
def main(args):
    imm = immlib.Debugger()
    
    if not args:
        imm.Log("### Immunity's Mark the tiny ones script###",focus=1)
        imm.Log("Command ok, but no args, using defaults")
    try:
        opts, argo = getopt.getopt(args, "f:c:m:")
    except getopt.GetoptError: #get args, if error, show usage
        usage(imm)
        return "Bad argument %s" % args[0]
    
    
    #tiny ones default list
    tinyones=[]
    tinyones.append("strcpy")
    tinyones.append("memcpy")
    tinyones.append("memmov")
    
    
    module=None
    function=None
    function_address=0
    comment="default comment"
    
    
    #parsing args
    for o,a in opts:
        if o == "-f":
            try:
                function = a
                function_address=imm.getAddress(function)
                imm.Log("%s address: 0x%8x" % (function,function_address),focus=1)
            except ValueError, msg:
                imm.Log("No function given, using the tiny ones")
        if o == "-c":
            comment = a
            imm.Log("Comment: %s" %comment)
        if o == "-m":
            if a and a != "ALL":
                try:
                    module = imm.getModule(a)
                    if not module:
                        return "Invalid module: %s" % a
                    else:
                        imm.Log("module: %s" %module.getName())
                        base = module.getBase()
                except ValueError, msg:
                    return "Invalid module: %s" % a
        else:
            regs=imm.getRegs()
            module = imm.findModule(regs['EIP']) # if no module given, use the one we are standing on
            if not module:
                return "Module?"
            else:
                imm.Log("module: %s" %module[0])
                base=module[1]
                
    #all data, find and mark
    if module == "ALL":
        mods = imm.getAllModules()
        for mod in mods:
            refaddr=imm.getInterCalls(mod.getBase())
            for a in refaddr.keys():
                op = imm.Disasm(a) 
                #imm.Log("op: %s"% op.comment)
                decoded=imm.decodeAddress(refaddr[a][0][2]) # decode destination
                if function_address != 0:
                    if function in decoded: #and ask if function name is in destination
                        imm.Log("From: 0x%08x - to 0x%08x" %(a,refaddr[a][0][0]))
                        imm.Log("Decoded destination: %s" % decoded)
                        imm.setComment(a,comment) #so, set your comment
                else:
                    for function in tinyones:
                        if function in decoded: #and ask if function name is in destination
                            imm.Log("From: 0x%08x - to 0x%08x" %(a,refaddr[a][0][0]))
                            imm.Log("Decoded destination: %s" % decoded)
                            imm.setComment(a,comment) #so, set your comment

                        
        
    else:
        regs=imm.getRegs()
        refaddr=imm.getInterCalls(regs['EIP'])
        for a in refaddr.keys():
            op = imm.Disasm(a) 
            #imm.Log("op: %s"% op.comment)
            decoded=imm.decodeAddress(refaddr[a][0][2]) # decode destination
            if function_address != 0:
                if function in decoded: #and ask if function name is in destination
                    imm.Log("From: 0x%08x - to 0x%08x" %(a,refaddr[a][0][0]))
                    imm.Log("Decoded destination: %s" % decoded)
                    imm.setComment(a,comment) #so, set your comment
            else:
                for function in tinyones:
                    if function in decoded: #and ask if function name is in destination
                        imm.Log("From: 0x%08x - to 0x%08x" %(a,refaddr[a][0][0]))
                        imm.Log("Decoded destination: %s" % decoded)
                        imm.setComment(a,comment) #so, set your comment
                

    return "mark finished executing"

            
        