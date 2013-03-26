#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

Additional feature of iterating through all DLL's added by Justin Seitz <jms@bughunter.ca> 

"""

import immlib
import getopt
import struct

DESC = """Get the RPC information of a loaded dll"""

def usage(imm):
    imm.log("!getrpc filename|all Get the RPC information of a loaded dll or for all loaded DLL's",focus=1)

def get_rpc_info(imm,mod,module_name):

    codeaddr = mod.getBase()
    size = mod.getSize()
    mem = imm.readMemory(codeaddr, size)
    ndx = 0
    offset = ndx
    Found = 0
    while 1:
        offset = mem[ndx:].find("\x04\x5d\x88\x8a")
        if offset == -1:
            break
        offset -= 0x18
        
        try:
            length = struct.unpack("L", mem[ndx+offset : ndx+offset+4])[0]
            if length == 0x44:
                Found += 1
                addr = codeaddr + ndx + offset
                
                imm.log("RPC SERVER INTERFACE found at: 0x%08x" % addr, address = addr)
                hu= struct.unpack("LHH",  mem[ndx+offset+4    : ndx+offset+0xc])
                hu2 = struct.unpack("!HLH", mem[ndx+offset+0xc : ndx+offset+0x14])
                uuid = "%08x-%04x-%04x-%04x-%08x%04x" % (hu[0], hu[1], hu[2], hu2[0], hu2[1], hu2[2])
                major,minor = struct.unpack("HH", mem[ndx+offset+0x14 : ndx+offset+0x18])
                imm.log("RPC UUID: %s (v%d.%d)" % (uuid, major, minor))
                imm.gotodisasmWindow(addr)
                imm.setComment(offset + codeaddr,      "Length")
                imm.setComment(offset + codeaddr+4,    "Interface UUID: %s (v%d.%d)" % (uuid, major, minor))
                imm.setComment(offset + codeaddr+0x18, "Transfer syntax")
                imm.setComment(offset + codeaddr+0x2c, "Dispatch Table")
                imm.setComment(offset + codeaddr+0x30, "RpcProtseqEndpointCount")
                imm.setComment(offset + codeaddr+0x34, "RpcProtseqEndpoint")
                imm.setComment(offset + codeaddr+0x38, "Default Manager")
                imm.setComment(offset + codeaddr+0x3c, "Interpreter Info")
                imm.setComment(offset + codeaddr+0x40, "Flags")
                interpreter_info = struct.unpack("L", mem[ndx+offset+0x3c : ndx+offset+0x3c+4] )[0]        
                function_list_addr = imm.readLong( interpreter_info + 4)
                dispatch_table = struct.unpack("L", mem[ndx+offset+0x2c : ndx+offset+0x2c+4] )[0]
                number = imm.readLong( dispatch_table )
                function_ptr = imm.readLong( dispatch_table + 4 )
                for a in range(0, number):
                    func = imm.readLong(function_list_addr+a*4)
                    imm.log("Function[%d]: 0x%08x" % (a , func), address = func, focus=1)
                for a in range(0, number):
                    func = imm.readLong(function_ptr+a*4)
                    imm.log("Function pointer [%d]: 0x%08x" % (a , func), address = function_ptr+a*4)
                    
        except Exception, msg:
            pass
        ndx += offset+0x20
    del mem
    if Found:
        imm.log("Module: %s END ===============================================================================" % module_name)
        return "Found %d interfaces on %s" % (Found, module_name)
    else:
        return "No interface found on %s" % module_name


def main(args):
    imm = immlib.Debugger()
    module_exists = False
    if not args:
        usage(imm)
        return "Incorrect number of arguments (No args)"
    if len(args) != 1:
        usage(imm)
        return "Incorrect number of arguments"
     
    
    
    if args[0].lower() == "all":
        mod_list = imm.getAllModules()
        for mod in mod_list.iteritems():
            module = imm.getModule(mod[0])
            sys_dll = module.getIssystemdll()
            
            if sys_dll == 0:
                imm.setStatusBar("Fetching RPC information for: %s" % mod[0])
                get_rpc_info(imm,module,mod[0])
        module_exists = True        
    else:
        
        mod = imm.getModule(args[0])
        
        if mod:
            module_exists = True
            imm.setStatusBar("Fetching RPC information for: %s" % args[0])
            get_rpc_info(imm,mod,args[0])
            
            
    if module_exists == False:
        return "Module not found"    
    else:
        return "Module information outputted, check the Log."
