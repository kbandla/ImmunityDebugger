#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

"""



DESC="""Analize the heap pattern of a executed function"""

import immlib
import immutils
import struct
from immlib import LogBpHook
from libheap import *
import libdatatype
import getopt

# RtlAllocateHeap Hook class
ALLOCLABEL = "Alloc Hook"
class RtlAllocateHeapHook(LogBpHook):
    def __init__(self, address):
        LogBpHook.__init__(self)
        #self.Heap = heap
        self.hookaddr = address
        self.Called = []
    def run(self,regs):
        """This will be executed when hooktype happens"""
        imm = immlib.Debugger()
        readaddr=""
        size=""
        
        res=imm.readMemory( regs['EBP'] + 8, 0xc)
        if len(res) != 0xc or not res:
            imm.log("RtlAllocateHeap: ESP seems to broken, unable to get args")
            return 0x0
        (heap, flags, size) = struct.unpack("LLL", res)
        #imm.log("RtlAllocateHeap(0x%08x, 0x%08x, 0x%08x)" % (heap, flags, size))        
        called = imm.getKnowledge( "heap_%08x" % self.hookaddr )
        if not called:
            called = []
        try:       
            callstack = imm.readLong( regs['EBP'] + 4)            
        except Exception:
            callstack = 0x0             

        called.append( (1, callstack, heap, flags, size, regs['EAX'] ) )            
        imm.addKnowledge("heap_%08x" % self.hookaddr, called, force_add = 0x1)
        
# RtlFreeHeap Hook class
FREELABEL = "Free Hook"
class RtlFreeHeapHook(LogBpHook):
    def __init__(self, address):
        LogBpHook.__init__(self)
        self.hookaddr = address
        
    def run(self,regs):
        """This will be executed when hooktype happens"""
        imm = immlib.Debugger()

        readaddr=""
        size=""
        
        res=imm.readMemory( regs['ESP'] + 4, 0xc)
        if len(res) != 0xc:
            imm.log("RtlFreeHeap: ESP seems to broken, unable to get args")
            return 0x0
        (heap, flags, size) = struct.unpack("LLL", res)
        called = imm.getKnowledge( "heap_%08x" % self.hookaddr )
        
        if not called:
            called = []
        try:        
            callstack = imm.readLong( regs['EBP'] + 4)            
        except Exception:
            callstack = 0x0

        called.append( (0, callstack, heap, flags, size) )            
        imm.addKnowledge("heap_%08x" % self.hookaddr, called, force_add = 0x1)

class EndHook(LogBpHook):
    def __init__( self, retaddr ):
        LogBpHook.__init__(self)
        self.retaddr = retaddr

    def run(self, regs):
        imm = immlib.Debugger()
            
        called = imm.getKnowledge("heap_%08x" %  self.retaddr)
        (ahook, fhook) = imm.getKnowledge("end_%08x" % self.retaddr) 
        ahook.UnHook()
        fhook.UnHook()
        win      = imm.createTable("Function Sniffing", ["Address", "Data"] )
        memleak  = {}
        freelist = {}   
        win.Log("Dumping the Heap Flow")
        if called:
            for res in called:
                if res[0] == 1:
                    type, callstack, heap, flag, size, ret = res
                    memleak[ ret ] = (callstack, heap, flag, size, ret)    
                    win.Log("Alloc(0x%08x, 0x%08x, 0x%08x) -> 0x%08x" %\
                            ( heap, flag, size, ret ), address = callstack )
                elif res[0] == 0:
                    type, callstack, heap, flag, size = res
                    if memleak.has_key( size):
                        del memleak[ size ]
                    else:
                        freelist[ size ] = (callstack, heap, flag, size)

                    win.Log("Free (0x%08x, 0x%08x, 0x%08x)" %\
                            ( heap, flag, size ), address = callstack )
   
        win.Log("Chunk freed but not allocated on this heap flow")          
        pheap = PHeap( imm )
        dt = libdatatype.DataTypes(imm)

        for a in freelist.keys():
            (callstack, heap, flag, base) = freelist[a]
            win.Log("Free (0x%08x, 0x%08x, 0x%08x)" %\
                    ( heap, flag, base ), address = callstack )
            

        win.Log("Memleak detected")                 
        for a in memleak.keys():   
            (callstack, heap, flag, size, ret) = memleak[a]
            win.Log("Alloc(0x%08x, 0x%08x, 0x%08x) -> 0x%08x" %\
                            ( heap, flag, size, ret ), address = callstack )

            chk = pheap.getChunks( ret - 8, 1)[0]
            chk.printchunk( uselog = win.Log, dt = dt )
        imm.log("Funsniff finished, check the newly created window")        
        self.UnHook()    

# Function Hook class
class FunctionHook(LogBpHook):
    def __init__( self, allocaddr, freeaddr, continuos = False):
        LogBpHook.__init__(self)
        #self.threadid = threadid
        self.allocaddr = allocaddr
        self.freeaddr = freeaddr
        self.continuos = continuos
        
    def run(self, regs):
        """This will be executed when hooktype happens"""
        imm = immlib.Debugger()
        # We will probably gonna need the threadid. Gather it through getEvent()
        readaddr=""
        size=""
        retaddr = imm.readLong( regs['EBP'] + 4)
        for a in regs:
            imm.log("%s:%08x" % (a, regs[a]))

        if not retaddr:
            self.UnHook()
            imm.log("Unhooking, wrong ESP")
            return 
        
        
        endhook = EndHook( retaddr )
        endhook.add("EndHook_%x"  % retaddr, retaddr)
        
        ahook = RtlAllocateHeapHook( retaddr)
        ahook.add( "Alloc_%08x"% retaddr, self.allocaddr)
        
        fhook = RtlFreeHeapHook( retaddr)
        fhook.add( "Free_%08x" % retaddr, self.freeaddr)
        imm.addKnowledge("end_%08x" % retaddr, (ahook, fhook) )
        
        imm.log("o Sniffing the selected Function", address = regs['EIP'])
        if not self.continuos:
            self.UnHook()
        
        
def getRet(imm, allocaddr, max_opcodes = 500):
    addr = allocaddr
    for a in range(0, max_opcodes):
        op = imm.disasmForward( addr )
        if op.isRet():
            if op.getImmConst() == 0xc:
                op = imm.disasmBackward( addr, 3)                   
                return op.getAddress()
        addr = op.getAddress()

    return 0x0

def usage(imm):
    imm.log( "!funsniff -a ADDRESS (-c)  Analize the heap pattern of a executed function" )      
    imm.log( " -a ADDRESS     Address of Function to fingerprint")
    imm.log( " -c             Continuos")

def main(args):
    imm          = immlib.Debugger()

    address   = 0x0
    continuos = False    
    if not args:
        usage(imm)
        return "Wrong Arguments (Check usage on the Log Window)"
        
    try:
        opts, argo = getopt.getopt(args, "a:c")
    except getopt.GetoptError:
        return "Wrong Arguments (Check usage on the Log Window)"

    for o,a in opts:
        if o == '-a':
            try:                
                address = int( a, 16 )
            except ValueError:
                usage(imm)                  
                return "Wrong Address (%s) % " % a
        elif o == '-c':
            continuos = True            

    if not address:
        return "Wrong Arguments (Check usage on the Log Window)"
            
    allocaddr = imm.getAddress("ntdll.RtlAllocateHeap" ) 
    freeaddr = imm.getAddress("ntdll.RtlFreeHeap" )
    allocaddr = getRet(imm, allocaddr, 800)
    
    if not allocaddr or not freeaddr:
        imm.log("Error, couldn't find the address of allocateHeap or freeHeap")
        return "Error resolving Address"

    imm.log("Func Sniffing starting")
    imm.log("o Setting the first hook")
    hook = FunctionHook( allocaddr, freeaddr )
    hook.add( "Func_%08x" % address, address)
    return "Hook set"

