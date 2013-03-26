#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

"""

DESC="""gflags"""

import getopt
import immlib
import libregistry

def usage(imm):
    imm.log("!gflags -[a|d|c] -m module   Enable and Disable Global Flags", focus=1)
    imm.log("-m   module    Module to set the global flags")
    imm.log("-a   tag       Set a Flag")
    imm.log("-d   tag       Unset a Flag")
    imm.log("-c             Clear Flags")
    imm.log("tags: ")
    for tag in libregistry.GFlagsTags:
        r = libregistry.GFlagsRef[tag]
        imm.log( "    %s  - %s" % ( tag, r[0] ) )

def main(args):
    imm = immlib.Debugger()
    
    try:
        opts, argo = getopt.getopt(args, "m:a:d:c", ["module=", "add=", "delete=", "clear"])
    except getopt.GetoptError:
        usage(imm)          
        return "Wrong Argument (Check Log Window)"
    
    add_f = []
    delete_f = []
    clear_f = False
    module = ""
    for o,a in opts:
        if o in ('-a', "--add"):
            add_f.append( a )
        elif o in ('-d', "--delete"):
            delete_f.append( a )
        elif o in ('-c', "--clear"):
            clear_f = True
        elif o in ('-m', "--module"):
            module = a

    gf = libregistry.GFlags( module) 
    
    if not clear_f:
        if add_f:
            curr = 0
            for tag in add_f:
                try:
                    r = gf.GetReferencebyName( tag )
                except Exception, msg:
                    usage(imm)
                    return "Error: %s" % str(msg)
                curr = curr | r[1]
            gf.Set( curr )
            imm.log("Global Flags added")
        if delete_f:
            curr = 0
            for tag in delete_f:
                try:
                    r = gf.GetReferencebyName( tag )
                except Exception, msg:
                    usage(imm)
                    return "Error: %s" % str(msg)
                curr = curr | r[1]
            gf.UnSet( curr )
            imm.log("Global Flags Deleted")

    else:
        gf.Clear()
        return "Global Flag cleared"
        
    if not clear_f:
        try:
            ret = gf.Print()
        except Exception:
            return "GlobalFlag not found"
        if module:
            txt = "Current Flags for module %s" % module
        else:
            txt = "Current Global Flags:"
        imm.log(txt)
        for (tag, r) in ret:
            imm.log("    %s: %s" % (tag, r[0]))
    return "Done"
            
