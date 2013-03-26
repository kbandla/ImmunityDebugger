#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

Immunity PyCommand Template

"""

__VERSION__ = '0.0'

import immlib
import getopt

DESC= "Immunity PyCommand Template" #description used by PyCommands GUI

def usage(imm):
    """ All the options"""
    imm.log("!template  example command")
    imm.log("!template [-a] [-b] [-c] ",focus=1) # focus the usage
    
    
def main(args):
    imm = immlib.Debugger()
    
    if not args:
        imm.log("### Immunity's PyCommand template ###")
        return "Command ok - no args" 
    try:
        opts, argo = getopt.getopt(args, "a:bc:")
    except getopt.GetoptError: #get args, if error, show usage
        usage(imm)
        return "Bad argument %s" % args[0]
    
    #parsing args
    for o,a in opts:
        if o == "-a":
            #processing args
            ret=processA(imm,a)
        elif o == "-b":
            ret=processB(imm,a)
        elif o == "-c":
            ret=processC(imm,a)
    
    #ret is the string shown at status bar
    return ret

            

def processA(imm,arg):
    """do whatever"""
    imm.log("Argument received: %s" % str(arg))
    return "Command ok with: %s" %str(arg) #string, string, string!

def processB(imm,arg):
    imm.log("Argument received: %s" % str(arg))
    return "Command ok with: %s" %str(arg)

def processC(imm,arg):
    imm.log("Argument received: %s" % str(arg))
    return "Command ok with: %s" %str(arg)
        