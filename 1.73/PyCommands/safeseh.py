#!/usr/bin/env python
"""
Immunity Debugger safeseh search

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""

__VERSION__ = '1.1'

import immlib
import getopt
from immutils import *
import struct

LOG_HANDLERS=True

DESC= "Looks for exception handlers registered with SafeSEH"

def usage(imm):
    imm.Log("!safeseh (-m module)",focus=1)
        
def main(args):
    imm = immlib.Debugger()
        
    #if not args:
    #    return "Incorrect number of arguments"
    
    try:
        opts, argo = getopt.getopt(args, "m:s")
    except getopt.GetoptError:
        usage(imm)
        return "Bad argument %s" % args[0]
       
    for o,a in opts:
        if o == "-m":
            try:
                #address = int(a, 16)
                module=a
            except ValueError, msg:
                return "Invalid module name: %s" % a
        
    allmodules=imm.getAllModules()
    table=imm.createTable('SafeSEH Table',['Module','Handler'])
    for key in allmodules.keys():
        mod=imm.getModule(key)
        mzbase=mod.getBaseAddress()
        peoffset=struct.unpack('<L',imm.readMemory(mzbase+0x3c,4))[0]
        pebase=mzbase+peoffset
        flags=struct.unpack('<H',imm.readMemory(pebase+0x5e,2))[0]
        if (flags&0x400)!=0:
            imm.Log('%s: SafeSEH protected'%(key))
            imm.Log('%s: No handler'%(key))
            continue
        numberofentries=struct.unpack('<L',imm.readMemory(pebase+0x74,4))[0]
        if numberofentries>10:
            sectionaddress,sectionsize=struct.unpack('<LL',imm.readMemory(pebase+0x78+8*10,8))
            sectionaddress+=mzbase
            data=struct.unpack('<L',imm.readMemory(sectionaddress,4))[0]
            condition=(sectionsize!=0) and ((sectionsize==0x40) or (sectionsize==data))
            #imm.Log('%s: %08x %04x %08x %08x %d'%(key,mzbase,flags,sectionaddress,sectionsize,condition))
            if condition==False:
                imm.Log('%s: *** SafeSEH unprotected ***'%(key))
                continue
            if data<0x48:
                imm.Log('%s: TODO check section 0xe!'%(key)) #checked in RtlCaptureImageExceptionValues() though I have never seen such a DLL/EXE
                continue
            sehlistaddress,sehlistsize=struct.unpack('<LL',imm.readMemory(sectionaddress+0x40,8))
            #imm.Log('%s: %08x %d'%(key,sehlistaddress,sehlistsize))
            if sehlistaddress!=0 and sehlistsize!=0:
                imm.Log('%s: SafeSEH protected'%(key))
                imm.Log('%s: %d handler(s)'%(key,sehlistsize))
                if LOG_HANDLERS==True:
                    for i in range(sehlistsize):
                        sehaddress=struct.unpack('<L',imm.readMemory(sehlistaddress+4*i,4))[0]
                        sehaddress+=mzbase
                        table.add(sehaddress,[key,'0x%08x'%(sehaddress)])
                        imm.Log('0x%08x'%(sehaddress))
                continue
            else:
                imm.Log('%s: TODO check section 0xe!'%(key)) #checked in RtlCaptureImageExceptionValues() though I have never seen such a DLL/EXE
                continue
        imm.Log('%s: *** SafeSEH unprotected ***'%(key))

    
    return "Check your table for results"
        
            