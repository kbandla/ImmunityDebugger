#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

Traceargs example

"""

__VERSION__ = '1.0'

DESC="""TraceArgs -> Find User supplied arguments into a given function"""

import immlib
import immutils
import getopt
modarg = []
visited = []
COUNT   = 100  # LOOP LIMIT

def usage(imm):
    imm.log( "!traceargs  Find user-supplied arguments into a given function" )      
    imm.log( "!traceargs -a ADDRESS -n ARG <-s> <-b>" )
    imm.log("   -a  ADDRESS    Address of the function")
    imm.log("   -n  ARG        Argument number you want to look for")
    imm.log("   -s             Wheter or not, show all the result (including non user-supplied)")    
    imm.log("   -b             Wheter or not, breakpoint on the calling instructions")

def main(args):
    imm=immlib.Debugger()
    if not args:
        usage(imm)
        return "Wrong Arguments (Check usage on the Log Window)"

    try:
        opts, argo = getopt.getopt(args, "a:n:sb")
    except getopt.GetoptError:
        usage(imm)
        return "Wrong Arguments (Check usage on the Log Window)"
    
    funcaddress = 0
    tracedarg = 0
    shownonusersupplied = False
    breakpointoncall = False
    
    for o,a in opts:
        if o == '-a':
            try:                
                funcaddress = int( a, 16 )
            except ValueError:
                usage(imm)                  
                return "Wrong Address (%s) % " % a
        elif o == '-n':
            try:                
                tracedarg = int( a, 16 )
            except ValueError:
                usage(imm)                  
                return "Wrong Trace Arg (%s) % " % a
        elif o == '-s':
            shownonusersupplied  = True            
        elif o == '-b':
            breakpointoncall = True
            
    if not funcaddress:
        usage(imm)                  
        return "Wrong Arguments. Address is missing"
    if not tracedarg:
        usage(imm)                  
        return "Wrong Arguments. Trace Argument is missing"
    references = imm.getXrefFrom( funcaddress )
    for ref in references:
        
        ret = imm.getTraceArgs( ref[0], tracedarg, shownonusersupplied)
        if ret:
            ( op, show ) = ret
            imm.log("Found user-supplied for arg_%d in %s"  % ( tracedarg, imm.disasm(ref[0]).result) , address = ref[0])
            if hasattr(op, 'type'): type = op.type
            else: type=""
            
            imm.log( "%s %s" % (op.getDisasm(), type), address = op.getAddress()  )
            for msg in show:
                imm.log( msg.getDisasm(), address = msg.getAddress() )
            imm.log("------")
            if breakpointoncall:
                imm.setBreakpoint( ref[0] )
    
    return 0
