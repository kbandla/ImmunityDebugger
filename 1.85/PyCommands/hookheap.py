#!/usr/bin/env python
"""
Hook on RtlAllocateHeap
"""

DESC = """Hook on RtlAllocateHeap/RtlFreeHeap and display information """
import immlib
from immlib import LogBpHook
import getopt
import struct

# RtlAllocateHeap Hook class
ALLOCLABEL = "Alloc Hook"
class RtlAllocateHeapHook(LogBpHook):
    def __init__(self, heap):
        LogBpHook.__init__(self)
        self.Heap = heap
        
    def run(self,regs):
        """This will be executed when hooktype happens"""
        imm = immlib.Debugger()
        #for a in regs:
            #imm.log("%s:%08x" % (a, regs[a]))
        readaddr=""
        size=""
        
        res=imm.readMemory( regs['ESP'] + 4, 0xc)
        if len(res) != 0xc:
            imm.log("RtlAllocateHeap: ESP seems to broken, unable to get args")
            return 0x0
        (heap, flags, size) = struct.unpack("LLL", res)
        if heap == self.Heap:
            imm.log("RtlAllocateHeap(0x%08x, 0x%08x, 0x%08x)" % (heap, flags, size))        

# RtlFreeHeap Hook class
FREELABEL = "Free Hook"
class RtlFreeHeapHook(LogBpHook):
    def __init__(self, heap):
        LogBpHook.__init__(self)
        self.Heap = heap
        
    def run(self,regs):
        """This will be executed when hooktype happens"""
        imm = immlib.Debugger()
        #for a in regs:
            #imm.log("%s:%08x" % (a, regs[a]))
        readaddr=""
        size=""
        
        res=imm.readMemory( regs['ESP'] + 4, 0xc)
        if len(res) != 0xc:
            imm.log("RtlFreeHeap: ESP seems to broken, unable to get args")
            return 0x0
        (heap, flags, size) = struct.unpack("LLL", res)
        if heap == self.Heap:
            imm.log("RtlFreeHeap(0x%08x, 0x%08x, 0x%08x)" % (heap, flags, size))        
            
            
def usage(imm):
    imm.log("!hookalloc     Hook on RtlAllocateHeap/RtlFreeHeap and display information")
    imm.log("-h             Heap to hook")
    imm.log("-a             Hook on RtlAllocateHeap")
    imm.log("-f             Hook on RtlFreeHeap")
    imm.log("-u             Disable Hooks")
    
def HookOn(imm, heap, LABEL,  HeapHook, bp_address, Disable):
    hookalloc = imm.getKnowledge( LABEL + "_%08x" % heap )
    if Disable:
       if not  hookalloc:
           imm.log("Error %s: No hook for heap 0x%08x to disable" % (LABEL, heap))
           return "No %s to disable for heap 0x%08x" % (LABEL, heap)
       else:
           hookalloc.UnHook()
           imm.log("UnHooked %s" % LABEL)
           imm.forgetKnowledge( LABEL + "_%08x" % heap )
           return "%s for 0x%08x heap unhooked" % (LABEL, heap) 
    else:
        if not hookalloc:
            hookalloc= HeapHook( heap )
            hookalloc.add( LABEL + "_%08x" % heap, bp_address)
            imm.log("Placed %s" % LABEL)
            imm.addKnowledge( LABEL + "_%08x" % heap, hookalloc )
        else:
            imm.log("HookAlloc for heap 0x%08x is already running" % heap)
        return "Hooking on RtlAllocateHeap"
#!/usr/bin/env python
    
"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""

def main(args):
    if not args:
        return "No arguments given"

    heap = None
    Disable = False
    AllocFlag = False
    FreeFlag = False
    imm = immlib.Debugger()
    
    try:
        opts, argo = getopt.getopt(args, "h:uaf")
    except getopt.GetoptError:
        imm.setStatusBar("Bad argument %s" % str(args))
        usage(imm)
        return 0
    
    for o,a in opts:
        if o == "-h" :
            try:
                heap = int(a, 16)
            except ValueError, msg:
                return "Invalid heap address: %s" % a
        elif o == "-u" :
            Disable = True
        elif o == "-a":
            AllocFlag = True
        elif o == "-f":
            FreeFlag = True
    
    ret = ""

    if heap:
        if AllocFlag:
            allocaddr = imm.getAddress("ntdll.RtlAllocateHeap" ) 
            ret = "Alloc Hook <%s>" % HookOn(imm, heap, ALLOCLABEL, RtlAllocateHeapHook, allocaddr, Disable)
        if FreeFlag:
            freeaddr = imm.getAddress("ntdll.RtlFreeHeap" ) 
            if ret:
                ret+= " - "
            ret +="Free Hook <%s>" %  HookOn(imm, heap, FREELABEL, RtlFreeHeapHook, freeaddr, Disable)
        return ret
    else:
        return "Please, select a correct Heap" 
                            
        
    
    


        
   
    
    
    
    


    
    
