#!/usr/bin/env python
"""
Immunity Debugger stackvars

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} Debugger API for python

stackvars.py - set comments around the code to follow stack variables size and content.

"""

__VERSION__ = "1.2"

import immlib
import immutils
import getopt
from libstackanalyze import *

DESC="Set comments around the code to follow stack variables size and content"

def usage(imm):
    imm.log("!stackvars address_or_expresion [steps_to_decode]")
    imm.log("%s" % DESC)
    imm.log("Note: each step represent one call further from the base function")

def main(args):
    imm = immlib.Debugger()

    if not args:
        imm.log("you must define the address of the function to analyze")
        usage(imm)
        return "not enough args"

    address = imm.getAddress(args[0])
    if address < 0:
        imm.log("invalid address or expresion")
        usage(imm)
        return "address error!"
    
    if len(args) > 1:
        steps_after = int(args[1])
    else:
        steps_after = 1

    imm.log("################# Immunity's StackVars ################")
    imm.log("Analyzing function %08X - %s..." % (address, imm.decodeAddress(address)))

    flow = FlowAnalyzer(imm, address, steps_after)
    Calls,varsHits,argsHits,varsSize = flow.getFlowInformation()


    imm.log("----------- code flow -------------")
    for start,data in Calls.iteritems():
        imm.log("function: %s" % imm.decodeAddress(start))
        for k,v in data.iteritems():
            imm.log("from: %s - to: %s - argc: %d - args:" % \
                    (imm.decodeAddress(k), imm.decodeAddress(v[0]), len(v[1])))
            for kk,vv in v[1].iteritems():
                imm.log("arg %d - data: %s" % (kk,str(vv)))
                imm.setComment(vv['addy'], flow.argInfo(start,k,kk))

    #paint args
    for start,data in argsHits.iteritems():
        for const in data:
            for hit in data[const]:
                imm.setComment(hit, "using arg[%d] of function: %s" % ((const-4)/4, imm.decodeAddress(start)))

    #paint vars
    for start,data in varsHits.iteritems():
        for const in data:
            try:
                size = varsSize[start][const]
            except KeyError:
                imm.log("local var size not found: addr: %08X, value: %d" % (start,const))
                size = "unknown"

            for hit in data[const]:
                imm.setComment(hit, "Local Var: %X - size: %s" % (const, size))

    imm.log("functionBegin: %08X" % flow.getFunctionBegin())

    imm.log("-------- size of variables --------")
    for start,data in varsSize.iteritems():
        imm.log("function: %s" % imm.decodeAddress(start))
        for const,size in data.iteritems():
            imm.log("lvar %X: %d" % (const,size))
    
    return "Done! see the log for details"
