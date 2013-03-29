"""
SymbolicExecutor usemode and API

imm = immlib.Debugger()
se = SymbolicExecutor(imm)

# Initialize the State Machine, if no regs/flags are provided they're obtained from the debugger.
se.initializeMachine(regs=None, flags=None)

# raise an UnconditionalStopException when the address is reached.
se.addStop(0x12345678)

# raise a ConditionalStopException if EAX == 0xcafecafe in ANY address.
se.addConditionalStop( ("EAX", Expression(0xcafecafe)), address=None )

# execute "python_callback" before the instruction, return True to replace the instruction completely.
se.addMonitor(python_callback, 0x12345678)

#execute the given python emulator instead of the native function. the python callback receives an args array
#it must return True if the emulation was successful, or False to indicate that the native function must be executed
se.addFunctionEmulator(python_callback, address=0x12345678, argc=3, cc="cdecl")


#use a dummy emulator to avoid calling a real function that could slow down the evaluation or for other purposes.
#it sets all volative registers to symbolic variables to acknowledge the fact that previous values on those registers
#could be overwriten by this function. The same is done with the return register.
se.addDummyEmulator(address=0x12345678, args=2, cc="fastcall")

#add a callback that would try to handle an execution exception
#more than one handler can be declared for any exception type, they will be executed in order until one of them
#returns True, meaning the exception was handled correctly.
#If there's no handler or any of them can handle the exception, it is re-raised to allow further handling from
#outside the class.
se.addExceptionHandler(UnsolvedJumpConditionException, python_callback)

"""
from x86smt.sequenceanalyzer import *
from x86smt.interceptor import *
import math
from time import time
from datetime import timedelta
from x86smt.prettysolver import *
import sys

class UnsolvedJumpConditionException(Exception):
    pass

class UndefinedAllocationSizeException(Exception):
    pass

class SymbolicAllocationSizeTooBigException(Exception):
    pass

class ReadAfterFreeException(Exception):
    pass

class WriteAfterFreeException(Exception):
    pass

class ReadUninitializedMemoryException(Exception):
    pass

class DoubleFreeException(Exception):
    pass

#triggered by AllocSize and free with the address to free/allocsize is not the base of a chunk, but some more complex expression
class IncorrectChunkAddressException(Exception):
    pass

class AllocSizeOverFreedMemoryException(Exception):
    pass

#this shouldn't happen, means there's a chunkvar that was not followed in the allocmem dictionary
#or that a chunkvar was not able to be returned from a SMT expression
class UnknownSymbolicallyAllocatedMemoryException(Exception):
    pass

class HeapOverflowOnWriteException(Exception):
    pass

class HeapOverflowOnReadException(Exception):
    pass

class ConditionalStopException(Exception):
    pass

class UnconditionalStopException(Exception):
    pass

def emulateAlloc(interceptor, args):
    """
    Emulate alloc and maintain an internal list of allocated chunks.
    Returned address is actually a SMT variable that represents the chunk.
    The set and get memory functions are used to enforce the rules for symbolic heap chunks.
    This way we always know we are working with dinamically allocated buffers.
    
    Receives one argument (size) and returns allocated address in EAX.
    """
    
    interceptor.sa.stats["alloc"]+=1
    
    size=interceptor.sa.state.solver.simplify(args[0])
    
    chunkvar = "CHUNK_0x%x" % interceptor.sa.nextallocaddr
    smtvar = interceptor.sa.state.solver.varExpr(chunkvar, interceptor.sa.state.solver.bv32bits) #ptr size
    
    tmp = interceptor.sa.state.solver.UConstFromExpr(size)
    if tmp == None:
        tmp = interceptor.sa.state.solver.exprString(size)
    else:
        tmp = "0x%x"%tmp
    interceptor.sa.imm.log("Alloc(%s)=%s"%(tmp, chunkvar), interceptor.sa.lastAddress)
    
    interceptor.sa.allocmem[chunkvar] = [smtvar, size, "B"]
    
    interceptor.sa.state.regs["EAX"] = smtvar #return the new address
    
    interceptor.sa.nextallocaddr+=1
    
    return True #everything went well
    
    
def emulateFree(interceptor, args):
    interceptor.sa.stats["free"]+=1
    
    chunkvar = interceptor.sa.getAllocChunkvar(args[0])
    if not chunkvar:
        interceptor.sa.reportError(UnknownSymbolicallyAllocatedMemoryException, args[0])
        
    info = interceptor.sa.getAllocInfo(chunkvar)
    
    if not interceptor.sa.state.solver.compareExpr(info[0], args[0]):
        interceptor.sa.reportError(IncorrectChunkAddressException, args[0])
    
    if info[2] == "F":
        interceptor.sa.reportError(DoubleFreeException, args[0])
    
    interceptor.sa.imm.log("Free(%s)"%chunkvar, interceptor.sa.lastAddress)
    
    interceptor.sa.allocmem[chunkvar][2] = "F" #mark chunk as free to detect read/write after free
    
    interceptor.sa.state.regs["EAX"] = interceptor.sa.state.solver.constExpr(0) #return NULL
    
    return True #everything went well

def emulateAllocSize(interceptor, args):
    interceptor.sa.stats["allocsize"]+=1
    
    chunkvar = interceptor.sa.getAllocChunkvar(args[0])
    if not chunkvar:
        interceptor.sa.reportError(UnknownSymbolicallyAllocatedMemoryException, args[0])
        
    info = interceptor.sa.getAllocInfo(chunkvar)
    
    if not interceptor.sa.state.solver.compareExpr(info[0], args[0]):
        interceptor.sa.reportError(IncorrectChunkAddressException, args[0])
    
    if info[2] == "F":
        interceptor.sa.reportError(AllocSizeOverFreedMemoryException, args[0])
    
    tmp = interceptor.sa.state.solver.UConstFromExpr(info[1])
    if tmp == None:
        tmp = interceptor.sa.state.solver.exprString(info[1])
    else:
        tmp = "0x%x"%tmp
    interceptor.sa.imm.log("AllocSize(%s)=%s"%(chunkvar,tmp), interceptor.sa.lastAddress)
    
    interceptor.sa.state.regs["EAX"] = interceptor.sa.state.solver.constExpr(info[1]) #return chunk size
    
    return True #everything went well

def emulateMemset(interceptor, args):
    counter=interceptor.sa.state.solver.UConstFromExpr(args[2])
    if counter == None:
        interceptor.sa.reportError(UndefinedRepeatCounterException, args[2])
    
    val = interceptor.sa.state.solver.simplify(interceptor.sa.state.solver.extractExpr(args[1], 0, 7))
    for x in xrange(0, counter):
        if x:
            addr=interceptor.sa.state.solver.addExpr(args[0], interceptor.sa.state.solver.constExpr(x))
        else:
            addr=args[0]
        
        interceptor.sa.setMemoryStateFromSolverState(addr, val, 8)
    
    return True
    
def emulateMemcpy(interceptor, args):
    counter=interceptor.sa.state.solver.UConstFromExpr(args[2])
    if counter == None:
        interceptor.sa.reportError(UndefinedRepeatCounterException, args[2])
    
    for x in xrange(0, counter):
        if x:
            dst=interceptor.sa.state.solver.addExpr(args[0], interceptor.sa.state.solver.constExpr(x))
            src=interceptor.sa.state.solver.addExpr(args[1], interceptor.sa.state.solver.constExpr(x))
        else:
            dst=args[0]
            src=args[1]
        
        srcval = interceptor.sa.getMemoryStateFromSolverState(src, 8)
        interceptor.sa.setMemoryStateFromSolverState(dst, srcval, 8)
    
    return True

class SymbolicSequenceAnalyzer(SequenceAnalyzer):
    def getAddressFromState(self, state):
        """
        Given a state expression computes the effective address.

        @type state: Solver Expression
        @param state: a solver expression describing a memory address
        """
        
        simplified = self.state.solver.simplify(state)
        addr = self.state.solver.UConstFromExpr(simplified)
        if addr == None:
            #The expression cannot be reflected to an effective address
            #we continue only if it's a symbolic heap address, reportError if not
            
            chunkvar = self.getAllocChunkvar(simplified)
            if  chunkvar == None:
                self.reportError(UndefinedMemoryException, simplified)
            
            #ugly optimization and return type confusion, but... whatever, optimization! \o/
            addr = (simplified, chunkvar)
        
        return addr
    
    def getAllocChunkvar(self, addr):
        simplified = self.state.solver.simplify(addr)
        names = self.state.solver.getVarDependency(simplified, True)
        
        chunkvar=None
        for name in names:
            if name[0:6] == "CHUNK_":
                if chunkvar != None: #an address that uses more than one CHUNK address, very weird, we cant support that, as we wouldn't know what AllocInfo return
                    return None
                chunkvar = name
        
        return chunkvar
        
    def getAllocInfo(self, chunkvar):
        """
        return the allocation information given a CHUNK variable name: [chunkvar, size, flag={B,F}]
        
        if the information cannot be recovered raise an exception.
        """
        
        if self.allocmem.has_key(chunkvar):
            return self.allocmem[chunkvar]
        
        self.reportError(UnknownSymbolicallyAllocatedMemoryException, tmp1)
    
    def checkHeapChunkBoundaries(self, addr, chunkinfo, exception):
        if self._debug:
            self.imm.log("Checking Heap Boundaries. addr=%s, chunk=%s, size=%s"%(addr, chunkinfo[0], chunkinfo[1]))
        
        #simplified_addr >= chunkbase + size ==> HeapOverflow
        
        #replace chunkvar with zero
        addr = self.state.solver.mergeExpr(addr, { self.state.solver.exprString(chunkinfo[0]) : self.state.solver.constExpr(0) })
        
        check = self.state.solver.geExpr(addr, chunkinfo[1])
        ret = self.state.solver.checkSat(check)
        if ret:
            self.state.solver.returnFromCheck()
            self.reportError(exception, addr)
        
    def setMemoryStateFromSolverState(self, state, value, size):
        """
        we repeat the mem functions here to support our symbolically allocated memory
        
        size is in bits.
        """
        
        self.stats["setmem"]+=1
        
        tmpstate=state
        
        tmp1 = self.getAddressFromState(state) #it raises an exception if the address is not constant
            
        if isinstance(tmp1, tuple):
            info = self.getAllocInfo(tmp1[1]) #chunkvar
            
            if info[2] == "F": #writing over freed memory
                self.reportError(WriteAfterFreeException, tmp1)
            
            #check chunk boundaries
            self.checkHeapChunkBoundaries(tmp1[0], info, HeapOverflowOnWriteException)
        
        if self._debug:
            if isinstance(tmp1, tuple):
                tmp1 = self.state.solver.exprString(tmp1[0])
            else:
                tmp1 = "0x%08x" % tmp1
            
            tmp2 = self.state.solver.UConstFromExpr(self.state.solver.simplify(value))
            if tmp2 == None: tmp2=self.state.solver.exprString(self.state.solver.simplify(value))
            else: tmp2 = "0x%x"%tmp2
            
            self.imm.log("Writing to %s, size: %d bytes, value=%s"%(tmp1, size/8, tmp2))
        
        #set bytes in reversed positions (following the little endian physical schema)
        for pos in range(0,size,8):
            self.state.memory[tmpstate] = self.state.solver.extractExpr(value, pos, pos+8-1)
            
            newtmpstate=self.state.solver.addExpr(tmpstate, self.state.solver.constExpr(1))
            if tmpstate != state:
                self.state.solver.deleteExpr(tmpstate)
            tmpstate=newtmpstate
        
        return True
    
    def getMemoryStateFromSolverState(self, state, size):
        """
        we repeat the mem functions here to support our symbolically allocated memory
        
        """
        
        self.stats["getmem"]+=1
        
        tmpstate = state
        ret = []
        info = None
        
        m_addr = self.getAddressFromState(state)
        if isinstance(m_addr, tuple):
            info = self.getAllocInfo(m_addr[1]) #chunkvar
            
            if info[2] == "F": #reading freed memory
                self.reportError(ReadAfterFreeException, m_addr[0])
            
            #check chunk boundaries
            self.checkHeapChunkBoundaries(m_addr[0], info, HeapOverflowOnReadException)
        
        #return the bytes positions reversed (following the physical position)
        for pos in range(0,size,8):
            
            # If the address being accessed has never been set or
            # retrieved from before then we initialize it with the
            # current value at that memory location
            if not self.state.memory.has_key(tmpstate):
                if info: #reading uninitialized mem
                    self.reportError(ReadUninitializedMemoryException, (m_addr, pos))
                else:
                    addr = m_addr + (pos / 8)
                    
                    if self._debug:
                        self.imm.log("Reading mem: %08x"%addr, addr)
                    
                    val = self.imm.readMemory(addr, 1)
    
                    if len(val) == 0:
                        self.reportError(MemoryOutOfBoundsException, addr)
                    
                    val_expr = self.state.solver.constExpr(ord(val), 8)
                    self.state.memory[tmpstate] = val_expr
            
            tmp=self.state.memory[tmpstate]
            ret.insert(0, tmp)
            
            newtmpstate=self.state.solver.addExpr(tmpstate, self.state.solver.constExpr(1))
            if tmpstate != state:
                self.state.solver.deleteExpr(tmpstate)
            tmpstate=newtmpstate
        
        tmp = ret.pop(0)
        for x in ret:
            tmp=self.state.solver.concatExpr(tmp, x)
        
        if self.simplifyState:
            simplified=self.state.solver.simplify(tmp)
            self.state.solver.deleteExpr(tmp)
        else:
            simplified=tmp
        return simplified
    
    def checkExceptions(self):
        """
        Stop if an exception MIGHT happen.
        """
        for name,expr in self.state.exceptions.iteritems():
            if self.state.solver.queryFormula(self.state.solver.boolNotExpr(expr)) != 1: #if not a VALID FALSE
                self.state.solver.returnFromCheck() #remove the assertions added to falsify the query
                return name
        return None
    
    def analyzeJcc(self, condition, finaladdress):
        self.stats["jcc"]+=1
        
        if self.state.solver.queryFormula(condition) == 1: #VALID TRUE
            #true branch reached, simulate a relative jump to that address
            self.state.EIP = self.state.solver.constExpr(finaladdress)
        
        else:
            self.state.solver.returnFromCheck() #remove the assertions added to falsify the query
            
            if self.state.solver.queryFormula(self.state.solver.boolNotExpr(condition)) != 1:
                self.state.solver.returnFromCheck() #remove the assertions added to falsify the query
                
                #both branches are SAT
                #the condition couldn't be solved, that's because it was influenced by some symbolic element
                self.reportError(UnsolvedJumpConditionException, (condition, finaladdress))

            else:
                #false branch, that means we dont need to do anything here
                pass

    def analyzeJMP(self, op):
        """
        Possibilities: JMP reg, JMP mem, JMP rel.
        (Far Jumps are not supported)
        """
        self.stats["jmp"]+=1
        
        if op.op1Type() == 0:
            #this is a rel16/rel32 jump
            self.state.EIP = self.state.solver.constExpr(op.jmpaddr) #use constant addresses for EIP
        else:
            dst = self.buildState(op, 0)
            dstval = self.getValueFromState(dst)
            self.state.EIP = dstval
        
        if self.state.isCall:
            self.state.isCall = False
            #save (caller, callee)
            try:
                self.state.callstack.append( (self.lastAddress, self.solveEIP()) ) #if EIP is not solved an exception is raised
            except UndefinedIPException:
                self.state.callstack.append( (self.lastAddress, 0) )
    
    def solveEIP(self):
        """
        simplified solveEIP, as we always use effective addresses, we just have to get the unsigned constant in the expression.
        If we cant get the constant it's because it is affected by a symbolic element.
        """
        simplified = self.state.solver.simplify(self.state.EIP)
        address=self.state.solver.UConstFromExpr(simplified)
        if address == None:
            #msg="Don't know how to solve EIP: %s"%self.state.solver.exprString(simplified)
            self.reportError(UndefinedIPException, simplified)
            return None
        return address


class SymbolicExecutor:
    def __init__(self, imm):
        self.imm = imm
        self.functionEmulators = {}
        self.stopConditions = {}
        self.exceptionHandlers = {}
        self._debug=False
        self.stateStack = []
        
        self.addrnames={}
        #for modname,syms in imm.getAllSymbols().iteritems():
            #for addr, info in syms.iteritems():
                #self.addrnames[addr] = modname.replace(".dll","").replace(".exe","") + "." + info.name

    def push(self):
        self.sa.push()
        
        for x in self.functionEmulators.values():
            if hasattr(x, "sa"):
                delattr(x, "sa")
        
        tosave = ( deepcopy(self.functionEmulators), deepcopy(self.stopConditions), deepcopy(self.exceptionHandlers), self._debug, deepcopy(self.sa.allocmem), \
                   self.sa.nextallocaddr, deepcopy(self.sa.stats) )
        
        self.stateStack.append(tosave)
        
        return len(self.stateStack) - 1
    
    def pop(self):
        self.sa.pop()
        
        ret = self.stateStack.pop()
        ( self.functionEmulators, self.stopConditions, self.exceptionHandlers, self._debug, self.sa.allocmem, self.sa.nextallocaddr, self.sa.stats ) = ret
        
        return ret
    
    def popto(self, stackLevel):
        while len(self.stateStack) > stackLevel:
            ret=self.pop()
        return ret
                
    def initializeMachine(self, regs=None, flags=None, prettysolver=True):
        if flags == None:
            flags={"_CF":0, "_PF":0, "_AF":0, "_ZF":0, "_SF":0, "_DF":0, "_OF":0}
            
        if regs == None:
            regs=self.imm.getRegs()
        
        self.sa = SymbolicSequenceAnalyzer(self.imm, r_model=regs, f_model=flags, m_model=True, prettysolver=prettysolver)
        self.sa.state.EIP=self.sa.state.solver.constExpr(regs["EIP"])
        self.sa.ignoredExceptions.append("LoopDetectedException") #we handle loops like a boss
        self.sa.ignoredExceptions.append("TooBigRepeatCounterException") #we have to execute them anyway
        self.sa._debug=self._debug
        if self._debug:
            self.sa._traceback=True
            
        self.sa.allocmem = {}
        self.sa.nextallocaddr = 0
        self.sa.stats={"instructions":0, "emulator-calls":0, "getmem":0, "setmem":0, "jcc":0, "jmp":0, "alloc":0, "free":0, "allocsize":0, "running-time":0, "worst-instr-time":0, "worst-instr-addr":0}
        self.sa.assertStack = []
        self.sa.revertedAsserts = []
        self.sa.se = self

    def addStop(self, address):
        return self.addConditionalStop(address=address)
    
    def addConditionalStop(self, condition=None, address=None):
        """
        It raises an exception on the emulation loop if the condition evaluates to TRUE over the specified address/address range
        
        A condition is a [list of] 2-tuple (reg/mem/flag, value) that is evaluated with the solver and if a VALID equality is found, it stops the execution.
        
        the memory comparisions are made byte-per-byte.
        
        If the condition is None, it raises a UnconditionalStopException instead of the ConditionalStopException.
        
        An address is a single DWORD or a list of 2-tuples (start-address, stop-address) where the condition should be evaluated.
        
        """
        
        if condition == None and address == None: #you cant outsmart me, my name is smart... maxwell smart
            return False
        
        if address == None:
            address = "ALL"
        else:
            if isinstance(address, str):
                address=self.imm.getAddress(address)
                if not address:
                    return False
            
        if not self.stopConditions.has_key(address):
            self.stopConditions[address]=[]
        
        if condition == None:
            self.stopConditions[address] = None #remove other conditions as this break is unconditional
        elif isinstance(self.stopConditions[address], list): #dont add a conditional break where an unconditional break was already added
            self.stopConditions[address].append(condition)
        else:
            return False
        
        return True
    
    def evaluateStops(self, address):
        if not self.stopConditions:
            return
        
        if self.stopConditions.has_key("ALL"):
            for cond in self.stopConditions["ALL"]:
                if self.evaluateStop(cond):
                    self.sa.reportError(ConditionalStopException)
        
        for k,v in self.stopConditions.iteritems():
            if k == "ALL":
                continue
            
            if (isinstance(k, tuple) and k[0] <= address and address <= k[1]) or (not isinstance(k, tuple) and k == address):
                if v == None:
                    self.sa.reportError(UnconditionalStopException)
                else:
                    for cond in v:
                        if self.evaluateStop(cond):
                            self.sa.reportError(ConditionalStopException)

    def evaluateStop(self, condition):
        if not isinstance(condition, list):
            condition=[condition]
        
        for cond in condition:
            key=cond[0]
            value=cond[1]
            
            if "_" in key:
                return self.sa.state.solver.compareExpr(self.sa.state.flags[key], value)
            elif isinstance(key, str):
                return self.sa.state.solver.compareExpr(self.sa.state.regs[key], value)
            else:
                if self.sa.state.memory.has_key(key):
                    return self.sa.state.solver.compareExpr(self.sa.state.memory[key], value)
                
        return False
            
    def addMonitor(self, function, address):
        """
        It allows you to execute your python code before the instruction is executed.
        
        If the callback function returns True it replaces the instruction analysis. 
        If not, the SequenceAnalyzer instruction analysis is called after the monitor callback.
        
        The monitor callback receives the SequenceAnalyzer instance.
        """
        
        if isinstance(address, str):
            return self.addFunctionEmulator(function, name=address, cc="custom")
        else:
            return self.addFunctionEmulator(function, address=address, cc="custom")
    
    def addFunctionEmulator(self, function, name=None, address=0, argc=0, cc="stdcall"):
        if address == 0:
            address=self.imm.getAddress(name)
        
        if name == None:
            #we use the name for variables too, so let's be sure we have one.
            name = "0x%08x"%address
        
        if address == 0 or address == None:
            return False
            
        if   cc == "stdcall":
            self.functionEmulators[address] = STDCALLFunctionInterceptor(address, name, argc, function)
        elif cc == "cdecl":
            self.functionEmulators[address] = CDECLFunctionInterceptor(address, name, argc, function)
        elif cc == "fastcall":
            self.functionEmulators[address] = FASTCALLFunctionInterceptor(address, name, argc, function)
        elif cc == "borlandfastcall":
            self.functionEmulators[address] = BORLANDFASTCALLFunctionInterceptor(address, name, argc, function)
        elif cc == "pascal":
            self.functionEmulators[address] = PASCALFunctionInterceptor(address, name, argc, function)
        elif cc == "thiscall":
            self.functionEmulators[address] = THISCALLFunctionInterceptor(address, name, argc, function)
        elif cc == "custom": #for people that knows what he's doing (basically if we want to replace a part of a function and not the entire thing)
                              #NOTE: it only sends the SequenceAnalyzer instance to the callback function
            self.functionEmulators[address] = CUSTOMFunctionInterceptor(address, name, function)
        else:
            return False
        
        return True
    
    def addDummyEmulator(self, name=None, address=0, argc=0, cc="stdcall"):
        return self.addFunctionEmulator(self.dummyFunctionEmulator, name, address, argc, cc)
    
    @staticmethod
    def dummyFunctionEmulator(interceptor, args):
        """
        just invalidate registers for symbolic execution.
        """
        
        for reg in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP"]:
            if reg == interceptor.returnreg:
                interceptor.sa.state.regs[reg] = interceptor.sa.state.solver.varExpr("RET_%s"%interceptor.name)
            elif reg not in interceptor.protectedregs:
                interceptor.sa.state.regs[reg] = interceptor.sa.state.solver.varExpr("UNK_%s"%interceptor.name)
        
        return True
    
    def addExceptionHandler(self, exctype, callback):
        """
        Add an exception handler for a specific exception type.
        
        - More than one handler can be registered for any exception type.
        - The handlers are executed sequentially until one of them returns True, meaning it handled the exception.
        
        Note: Unhandled exceptions are re-raised.
        """
        
        if not self.exceptionHandlers.has_key(exctype):
            self.exceptionHandlers[exctype]=[]
        self.exceptionHandlers[exctype].append(callback)
            
    def run(self):
        """
        Main emulation loop, it tries to handle the exceptions that occur as part of the emulation using the registered handlers, but if it cant, the
        exception is re-raised, so any call to run() should be enclosed inside a try/except block.
        
        """
        
        starttime=time()
        while True:
            try:
                instrtime=time()
                address=self.sa.solveEIP()
                
                #raises an exception if it has to stop
                self.evaluateStops(address)
                    
                if self.functionEmulators and self.functionEmulators.has_key(address):
                    self.sa.stats["emulator-calls"]+=1
                    if self.functionEmulators[address].run(self.sa) == False:
                        #if the run function returns False, it means the emulator failed and we need to do the job by ourself here
                        self.sa.analyzeNext()
                else:
                    self.sa.analyzeNext()
            
            except:
                (exctype, value, traceback) = sys.exc_info()
                
                if isinstance(value, exctype):
                    value = value.args
                    if isinstance(value, tuple) and len(value) == 1:
                        value = value[0]

                #unhandled exceptions are re-raised
                if not self.exceptionHandlers.has_key(exctype):
                    raise
                
                #more than one handler can be registered for an exception's type
                handled=False
                for handler in self.exceptionHandlers[exctype]:
                    handled=handler(exctype, value, self, address)
                    if handled: break
                
                #exceptions that couldn't be handled are re-raised
                if not handled:
                    raise
                
            #if no exceptions arised
            self.sa.state.simplify()
            self.sa.stats["instructions"]+=1
            instrtime=time() - instrtime
            if self.sa.stats["worst-instr-time"] < instrtime:
                self.sa.stats["worst-instr-time"] = instrtime
                self.sa.stats["worst-instr-addr"] = address
            self.sa.stats["running-time"]=time()-starttime

            #inform stats periodically
            if self.sa.stats["running-time"] % 10 < 1:
                self.informStats()
            elif self._debug:
                self.informStats()

    def informStats(self):
        self.imm.log("################ Statistics ###################")
        keys=self.sa.stats.keys()
        keys.sort()
        for k in keys:
            v=self.sa.stats[k]
            if "time" in k:
                self.imm.log("%s:%s"%(k, timedelta(seconds=v)))
            elif "addr" in k:
                self.imm.log("%s:0x%08x"%(k, v),v)
            else:
                self.imm.log("%s:%s"%(k, v))
                
        self.imm.log("Current Instruction:0x%08x"%self.sa.lastAddress, self.sa.lastAddress)
        
        self.imm.log("############## Symbolic Heap ##################")
        keys=self.sa.allocmem.keys()
        keys.sort()
        for k in keys:
            tmp = self.sa.state.solver.UConstFromExpr(self.sa.allocmem[k][1])
            if tmp == None:
                tmp = self.sa.state.solver.exprString(self.sa.allocmem[k][1])
            else:
                tmp = "0x%x"%tmp
            self.imm.log("%s - size=%s - state=%s"%(k, tmp, self.sa.allocmem[k][2]))
            
            #get content
            buf=[]
            for x in range(0, 16):
                addr = self.sa.state.solver.addExpr(self.sa.allocmem[k][0], self.sa.state.solver.constExpr(x))
                if self.sa.state.memory.has_key(addr):
                    val = self.sa.state.memory[addr]
                    intval = self.sa.state.solver.UConstFromExpr(val)
                    if intval == None:
                        val = self.sa.state.solver.exprString(val)
                    else:
                        val = "%02X"%intval
                else:
                    val = "UINIT"
                
                buf.append(val)
            
            self.imm.log("%s"%" | ".join(buf))
            self.imm.log("")

        self.sa.state.printRegisters(self.imm)
        
        self.imm.log("################## Callstack ######################")
        for x in self.sa.state.callstack:
            funname=""
            if self.addrnames.has_key(x[1]):
                funname=" (%s)"%self.addrnames[x[1]]
            self.imm.log("Caller=0x%08x, Callee=0x%08x%s"%(x[0], x[1], funname), x[0])
        
