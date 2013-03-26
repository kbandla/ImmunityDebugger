import socket
import struct
import xmlrpclib
import traceback
import base64
from immlib import *
from immutils import *
import getopt

DESC="""Hooks the NDR unmarshalling routines and prints them out so you can see which ones worked"""


#############################################################################
class set_hooks(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)
        self.description=""
        
        return 

    #########################################################################
    def run(self,regs):
        '''

        '''
        imm = Debugger()
        imm.log("%s"%self.description)
        return 

def usage(imm):       
    imm.log("!hookndr.py")
    imm.log("%s" % DESC)
    imm.log("-D               (to uninstall hook)")
    imm.log("-h This help")

# The main routine that gets run when you type !packets
def main(args):

    imm = Debugger()
    imm.ignoreSingleStep("CONTINUE")
    try:
        opts,argo = getopt.getopt(args, "Dh")
    except:
        return usage(imm)
    xmlhost=""
    xmlport=0
    for o,a in opts:
        if o == "-D":
            ndrhooks=imm.getKnowledge("ndrhooks")
            if not ndrhooks:
                imm.log("Could not find hooks to delete!")
                return "Did not find hook to delete"
            for hooker in ndrhooks:
                imm.removeHook(hooker)
                #now forget about that hook
            imm.forgetKnowledge("ndrhooks")
            return "Unhooked our ndr hooks"
        if o =="-h":
            return usage(imm)

    #otherwise it's time to hook some functions! Horray!
    #these functions are all in RPCRT4.dll
    #you know what would be good, being able to get all these automatically by listing names
    #and then looking for Ndr*Unmarshall!
    names= ["NdrPointerUnmarshall","NdrNonConformantStringUnmarshall","NdrNonEncapsulatedUnionUnmarshall"]
    names+=["NdrRangeUnmarshall","NdrSimpleStructUnmarshall","NdrSimpleTypeUnmarshall","NdrUserMarshalUnmarshall"]
    names+=["NdrVaryingArrayUnmarshall","NdrXmitOrRepAsUnmarshall","NdrByteCountPointerUnmarshall","NdrClientContextUnmarshall"]
    names+=["NdrComplexArrayUnmarshall","NdrConformantArrayUnmarshall","NdrConformantStringUnmarshall","NdrConformantStructUnmarshall"]
    names+=["NdrConformantVaryingArrayUnmarshall","NdrConformantVaryingStructUnmarshall","NdrEncapsulatedUnionUnmarshall"]
    names+=["NdrFixedArrayUnmarshall","NdrInterfacePointerUnmarshall"]
    hooks=[]
    for functionname in names:
        # Find the addresses of the functions we want to hook
        # Then register the hooks
        addy = imm.getAddress("RPCRT4."+functionname)
        imm.log(functionname+ " found at 0x%x"%addy)
        if addy == -1:
            imm.log("Could not locate %s"%functionname)
            continue
        
        # Set the hooks - this is the start hook
        hooker = set_hooks()
        hooker.description="Entering: %s"%functionname
        ret=hooker.add(hooker.description,  addy)
        if ret==-1:
            imm.log("Hooking add failed!")
        else:
            hooks+=[hooker.description]
            
        func = imm.getFunction( addy )
        endaddies=imm.getFunctionEnd( func) #get the address of all the rets of the function
        for addy in endaddies:
            # Set the hooks
            hooker = set_hooks()
            #hooker.description="Leaving: %s"%functionname
            ret=hooker.add(hooker.description,  addy)
            if ret==-1:
                imm.log("Hooking add failed!")
            else:
                hooks+=[hooker.description]
            
    imm.log("Added %d hooks"%(len(hooks)))
    imm.addKnowledge("ndrhooks",hooks)
    return "Network hooks in place."


