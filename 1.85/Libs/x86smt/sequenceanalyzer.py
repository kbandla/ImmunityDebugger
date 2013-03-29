from immlib import *
import cPickle
import traceback
import getopt
import string

from solver_cvc3 import Solver
from prettysolver import *
from binascii import crc32
from copy import deepcopy, copy
import operations #abstraction
import sys
import time

class MyDebugger(Debugger):
    def __init__(self, template="sequenceanalyzer-log-"):
        super(MyDebugger, self).__init__()
        self.datetime=time.strftime("%Y%m%d-%H%M%S")
        self.template=template

    def log(self, msg, address = 0,highlight = False, gray = False , focus = 0):
        if gray and not highlight:
            highlight = -1
        
        fd=open("%s%s.txt"%(self.template,self.datetime),"ab")
        fd.write("%08X:%s\n"%(address,msg))
        fd.close()
        return debugger.add_to_list( address, int(highlight), msg[:255],focus)

class MemoryDictionary(dict):
    """
    Maintains a list of memory addresses and values.
    Keys might be an expression, an expression dump or a memory key hash (MEM<CRC32>)
    Values must be expressions.
    If we try to retrieve a key that was not set before, a new expression is created to handle this undefined memory access.
    This new expression is a 8bits bitvector variable of name VAL<CRC32>
    CRC32=crc32(key expression dump)
    
    An internal dictionary of sources maintains the list of expressions dumps associated with the MEM<CRC32> keys. (self.sources)
    Antoher dictionary maintains a map of expressions created to handle undefined memory. (self.undefvalues)
    """

    def __init__(self, solver, *args, **kwargs):
        if len(args):
            dict.__init__(self, args)
        elif len(kwargs):
            dict.__init__(self, kwargs)
        else:
            dict.__init__(self)

        self.sources={}
        self.undefvalues={}
        self.solver=solver
    
    def __contains__(self, key):
        return self.has_key(key)
    
    def has_key(self, key):
        expkey=None
        crc=None
        if (isinstance(self.solver, PrettySolver) and isinstance(key, Expression)) or \
           (not isinstance(self.solver, PrettySolver) and (isinstance(key, int) or isinstance(key, long))):
            #this is an Expr
            expkey=self.solver.simplify(key)
            key=self.solver.dumpExpr(expkey, calchash=True)
            crc=self.solver.crc % (1<<32)
        
        if isinstance(key, tuple):
            #this is an Expr Dump
            if crc == None:
                crc = self.solver.hashExpr(self.solver.loadExpr(key))
            
            #key => MEM<CRC32> now
            key="MEM%08X"%crc
        
        return dict.has_key(self, key)

    def __getitem__(self, key):
        expkey=None
        crc=None
        if (isinstance(self.solver, PrettySolver) and isinstance(key, Expression)) or \
           (not isinstance(self.solver, PrettySolver) and (isinstance(key, int) or isinstance(key, long))):
            #this is an Expr
            expkey=self.solver.simplify(key)
            key=self.solver.dumpExpr(expkey, calchash=True)
            crc=self.solver.crc % (1<<32)
        
        if isinstance(key, tuple):
            #this is an Expr Dump
            if crc == None:
                crc = self.solver.hashExpr(self.solver.loadExpr(key))
            
            #key => MEM<CRC32> now
            newkey="MEM%08X"%crc
            
            if not self.sources.has_key(newkey):
                #for the case when we set a mem value by memHASH and we retrieve it by expr or dump
                if dict.has_key(self, newkey):
                    self.sources[newkey]=key #store the new source information
                else:
                    #if we try to get an non-existant key, just create an unresolved value for it
                    if expkey == None:
                        self.__setitem__(key, None)
                    else:
                        self.__setitem__(expkey, None)
            key=newkey
        
        if not dict.has_key(self, key):
            #if we try to get an non-existant key, just create an unresolved value for it
            self.__setitem__(key, None)
        
        return dict.__getitem__(self, key)
    
    def __setitem__(self, key, value):
        crc=None
        if (isinstance(self.solver, PrettySolver) and isinstance(key, Expression)) or \
           (not isinstance(self.solver, PrettySolver) and (isinstance(key, int) or isinstance(key, long))):
            #this is an Expr
            key=self.solver.dumpExpr(self.solver.simplify(key), calchash=True)
            crc=self.solver.crc % (1<<32)

        if isinstance(key, tuple):
            #this is an Expr Dump
            if crc == None:
                crc = self.solver.hashExpr(self.solver.loadExpr(key))
            
            newkey="MEM%08X"%crc
            if not self.sources.has_key(newkey):
                self.sources[newkey]=key
            key=newkey
        
        if value == None:
            tmp=key.replace("MEM","VAL")
            if not self.undefvalues.has_key(tmp):
                var=self.solver.lookupVar(tmp)
                if not var:
                    value = self.solver.varExpr(tmp, self.solver.bv8bits)
                else:
                    value = var[0]
                self.undefvalues[tmp]=value
            else:
                value=self.undefvalues[tmp]
        
        return dict.__setitem__(self, key, value)
    
    def simplify(self):
        for key in self.keys():
            value=self.solver.simplify(dict.__getitem__(self,key))
            dict.__setitem__(self, key, value)
    
    def prettify(self):
        if isinstance(self.solver, PrettySolver):
            return
        
        self.solver = PrettySolver(self.solver)
        for key in self.keys():
            value=Expression(self.solver, dict.__getitem__(self,key))
            dict.__setitem__(self, key, value)
        
        for key in self.undefvalues.keys():
            self.undefvalues[key] = Expression(self.solver, self.undefvalues[key])
            
    def getIndexes(self, mem, recursive=True):
        """
        Return a set of variable indexes for a given mem address hash.
        
        recursive decides if it should add indexes recursively or not.
        """
        
        exp=self.solver.loadExpr(self.sources[mem])
        indexes=set()
        for var in self.solver.getVarDependency(exp, return_name=True):
            if var[0:3] == "VAL" and recursive:
                mem=var.replace("VAL","MEM")
                indexes=indexes.union(self.getIndexes(mem, recursive=True)) #recursive call
            else:
                indexes.add(var)
        return indexes

class LazyDictionary(dict):
    def __init__(self, *args, **kwargs):
        if len(args):
            dict.__init__(self, args)
        elif len(kwargs):
            dict.__init__(self, kwargs)
        else:
            dict.__init__(self)

        self.needsupdate=False
        self.updatecallback=None
        self.updateargs=()
    
    def __getattribute__(self, name):
        if name in ("__repr__", "__cmp__", "__getitem__", "copy", "items", "iteritems", "itervalues", "values", "update", "get", "setdefault", "pop", "popitem", "__iter__") and self.needsupdate:
            self.needsupdate=False
            self.updatecallback(*self.updateargs)
        
        return object.__getattribute__(self, name)

class ConditionalBranchException(Exception):
    pass

class ConditionalJumpException(Exception):
    pass
    
class UnexpectedException(Exception):
    pass
    
class MemoryOutOfBoundsException(Exception):
    pass

class UndefinedMemoryException(Exception):
    pass

class UndefinedIPException(Exception):
    pass

class IPNonExecutablePageException(Exception):
    pass

class InvalidInstructionException(Exception):
    pass

class LoopDetectedException(Exception):
    pass

class UnsupportedOpcodeException(Exception):
    pass

class ProcessorException(Exception):
    pass

class UndefinedRepeatCounterException(Exception):
    pass

class TooBigRepeatCounterException(Exception):
    pass

class StateMachine:
    def __init__(self, r_model=None, f_model=None, solver=None):
        """
        @type r_model: Dict
        @param r_model: A dictionary mapping registers to concrete 
            values. Any registers not described in this dict will
            be described as undefined to the solver which effectively
            implies they are entirely user controlled and can 
            therefore be assigned any value by the solver when looking
            for a satisfying assignment

        @type f_model: Dict
        @param f_model: A dictionary mapping flags to concrete 
            values. Any flags not described in this dict will
            be described as undefined to the solver which effectively
            implies they are entirely user controlled and can 
            therefore be assigned any value by the solver when looking
            for a satisfying assignment
            
        @type solver: Solver/PrettySolver instance
        @param solver: If provided, use this solver instead of creating a new one
        """
        
        self._debug = False
        if solver:
            self.solver = solver
        else:
            self.solver = Solver()
        self.initState(r_model, f_model)
        self.stack = []
        self.callstack = []
        self.isCall = False

    def __getstate__(self):
        """
        return a dict with the information that should be saved when we use a cPickle or copy function.
        """
        
        tmp1={}
        for key,value in self.regs.iteritems():
            tmp1[key]=self.solver.dumpExpr(value)
        
        tmp2a={}
        tmp2b=self.memory.sources
        tmp2c=self.memory.undefvalues.keys()
        for key,value in self.memory.iteritems():
            tmp2a[key]=self.solver.dumpExpr(value)
        
        tmp3={}
        for key,value in self.flags.iteritems():
            tmp3[key]=self.solver.dumpExpr(value)
            
        tmp4={}
        for key,value in self.exceptions.iteritems():
            tmp4[key]=self.solver.dumpExpr(value)
        
        EIP=self.solver.dumpExpr(self.EIP)
        
        return cPickle.dumps((tmp1,tmp2a,tmp2b,tmp2c,tmp3,tmp4,EIP), cPickle.HIGHEST_PROTOCOL)
    
    def __setstate__(self, state):
        (tmp1,tmp2a,tmp2b,tmp2c,tmp3,tmp4,EIP) = cPickle.loads(state)
        
        for x in tmp2c:
            self.memory.undefvalues[x]=self.solver.varExpr(x, self.solver.bv8bits)
        
        self.memory.sources=tmp2b
        for key,val in tmp2a.iteritems():
            self.memory[key]=self.solver.loadExpr(val)
        
        for key,value in tmp1.iteritems():
            self.regs[key]=self.solver.loadExpr(value)
            
        for key,value in tmp3.iteritems():
            self.flags[key]=self.solver.loadExpr(value)
        
        for key,value in tmp4.iteritems():
            self.exceptions[key]=self.solver.loadExpr(value)
        
        self.EIP=self.solver.loadExpr(EIP)
        
        return True
    
    def __getinitargs__(self):
        return ()
    
    def initState(self, r_model=None, f_model=None):
        r_names = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP"]
        f_names = ["_CF", "_PF", "_AF", "_ZF", "_SF", "_DF", "_OF"]
        self.regs = {}
        self.flags = LazyDictionary()
        
        for r_name in r_names:
            if r_model and r_name in r_model:
                val = r_model[r_name]
                self.regs[r_name] = self.solver.constExpr(val, 32)
            else:
                self.regs[r_name] = self.solver.varExpr(r_name)
        
        for f_name in f_names:
            if f_model and f_name in f_model:
                if f_model[f_name]:
                    self.flags[f_name] = self.solver.true
                else:
                    self.flags[f_name] = self.solver.false
            else:
                self.flags[f_name] = self.solver.varExpr(f_name, self.solver.booltype)

        #even when we can't handle exceptions, we can provide constrains to avoid triggering one and by doing so, to lose control over the state of the processor
        self.exceptions = { "#DE":self.solver.false, "#BP":self.solver.false, "#OF":self.solver.false, "#BR":self.solver.false }
        
        self.memory = MemoryDictionary(self.solver)
        self.EIP = self.solver.varExpr("EIP")
    
    def writeMemory(self, address, value):
        """
        address is an Expression
        value is an Expression which size is divisible by 8
        """
        
        tmpstate=address
        valsize=self.solver.getBitSizeFromExpr(value)
        
        size=((valsize+7)//8)*8 #rounded up to 8bits
        if valsize != size:
            value=self.solver.zeroExtendExpr(value, size)
        
        #set bytes in reversed positions (following the physical schema)
        for pos in range(0,size,8):
            self.memory[tmpstate] = self.solver.extractExpr(value, pos, pos+8-1)
            
            newtmpstate=self.solver.addExpr(tmpstate, self.solver.constExpr(1))
            if tmpstate != address:
                self.solver.deleteExpr(tmpstate)
            tmpstate=newtmpstate
        
        return True
    
    def readMemory(self, address, size):
        """
        This function retrieves the value associated with the memory
        location denoted by address. The argument 'address' should be a
        solver expression. The value associated with this 'memory location'
        will also be a solver expression.

        @type address: Expression
        @param address: An expression denoting a memory location

        @type size: Int
        @param size: The size of the memory location in bytes

        @rtype: Expression
        @return: The expression associated with the memory location
            denoted by address
        """

        tmpstate = address
        ret = []
        
        #return the bytes positions reversed (following the physical position)
        for pos in range(0,size):
            tmp=self.memory[tmpstate]
            ret.insert(0, tmp)
            
            newtmpstate=self.solver.addExpr(tmpstate, self.solver.constExpr(1))
            if tmpstate != address:
                self.solver.deleteExpr(tmpstate)
            tmpstate=newtmpstate
        
        tmp = ret.pop(0)
        for x in ret:
            tmp=self.solver.concatExpr(tmp, x)
        simplified=self.solver.simplify(tmp)
        self.solver.deleteExpr(tmp)
        return simplified
    
    def hashState(self):
        #there's no possible key collision
        hashes={}
        for k,v in self.regs.iteritems():
            if self.solver.exprString(v) != k:
                hashes[k]=self.solver.hashExpr(v)
        for k,v in self.flags.iteritems():
            if self.solver.exprString(v) != k:
                hashes[k]=self.solver.hashExpr(v)
        for k,v in self.memory.iteritems():
            hashes[k]=self.solver.hashExpr(v)
        
        if self.solver.exprString(self.EIP) != "EIP":
            hashes["EIP"]=self.solver.hashExpr(self.EIP)
        
        return hashes
    
    def __hash__(self):
        """
        returns a single CRC32 value that represents the entire state machine.
        """
        
        ret=0
        for k,v in self.hashState().iteritems():
            ret=crc32("%s%08x"%(k,v), ret)
        
        return self.crc % (1<<32)
    
    def calcProperties(self):
        """
        Encode state of registers in a single number per reg:
        reg=EAX,EBX,ECX,EDX,ESI,EDI,EBP,ESP,EIP
        - for each reg:
          - modified (1 bits)
          - affected by reg (9 bits + 1 for flags)
          - affected by mem, indexed by regs (9 bits + 1 for flags + 1 for indep constant)
        For each flag encode 1 if modified (order=CPAZSDO)
        
        Returns a 2-tuple (regProps dictionary, flagProps integer)
        
        Properties MAP:
        2211111111110000000000
        1098765432109876543210
        ----------------------
        MMMMMMMMMMMFEEEEEEEEEM
        CFEEEEEEEEELISBDSDCBAO
        OLISBDSDCBAAPPPIIXXXXD
        NAPPPIIXXXXG         I
        SG                   F
        T
        """
        
        #calc properties related to registers
        regProps={}
        regs=["EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP"]
        for reg in regs:
            prop=0
            usesmem=False
            usesindexes=False
            
            if reg == "EIP":
                val = self.EIP
            else:
                val=self.regs[reg]
            
            if self.solver.exprString(val) != reg:
                prop|=1 #modified
            
                for var in self.solver.getVarDependency(val, return_name=True):
                    if "_" in var:
                        #affected by a flag
                        prop|=1 << 1 + 9
                    elif var[0:3] == "VAL": #depends on an undefined memory value
                        usesmem=True
                        mem=var.replace("VAL","MEM")
                        for i in self.memory.getIndexes(mem):
                            usesindexes=True
                            if "_" in i:
                                #mem index is a flag
                                prop|=1 << 1 + 9 + 1 + 9
                            else:
                                try:
                                    idx=regs.index(i)
                                except ValueError:
                                    continue #it uses some index we dont encode
                                prop|=1 << idx + 1 + 9 + 1
                    else:
                        try:
                            idx=regs.index(var)
                        except ValueError:
                            continue #it uses some index we dont encode
                        prop|=1 << idx + 1
                if usesmem and not usesindexes: #this is a deref of a constant
                    prop|=1 << 1+9+1+9+1
            
            regProps[reg]=prop
        
        #calc properties related to flags
        c=0
        flagProps=0
        for f in "CPAZSDO":
            flagProps |= int(self.solver.exprString(self.flags["_%sF"%f]) != "_%sF"%f) << c
            c+=1
    
        return (regProps, flagProps)

    def regMapToTuple(self, regmap):
        regs=["EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP","FLAG","CONST"]
        mybin=lambda num: "".join([str((num >> y) & 1) for y in range(0, 22)]) #reversed binary string
        regmap = mybin(regmap)
        
        regtuple = []
        memtuple = []
        if regmap[0] == "1":
            c=0
            for r in regmap[1:]:
                if r == "1":
                    if c < 10:
                        regtuple.append(regs[c])
                    else:
                        memtuple.append(regs[c-10])
                c+=1
            
            if not memtuple and not regtuple:
                regtuple.append("CONST")
        
        return (tuple(regtuple), tuple(memtuple))

    def flagMapToTuple(self, flagmap):
        c=0
        ret=[]
        for f in "CPAZSDO":
            if flagmap & (1 << c):
                ret.append(f)
            c+=1
        return ",".join(ret)
    
    def calcComplexity(self, regProps, flagProps):
        """
        Complexity index rules:
        - [1] add 4 for each modified reg
        - [2] add 1 for each related reg/flag bit
        - [3] add 2 for each related mem deref
        - [4] add 2 for each mem dword accessed
        - [5] add RETN const/4 if possible
        - [6] add 1 if flags are modified
        - [7] add 1 for each constant modifing a reg
        """
        
        complexity = 0
        mybin=lambda num: "".join([str((num >> y) & 1) for y in range(22-1, -1, -1)])
        for v in regProps.values():
            if v:
                complexity+=4  #[1]
            
            if v == 1: #just modified means equal to a constant
                complexity+=1  #[7]
            else:
                binv=mybin(v)
                complexity+=len(binv[11:21].replace("0",""))  #[2]
                
                complexity+=len(binv[0:11].replace("0",""))*2 #[3]
        
        complexity += ((len(self.memory.keys())+3)//4)*2 #[4]
        
        espvar = self.solver.lookupVar("ESP")
        if espvar != False:
            self.solver.push()
            self.solver.assertFormula(self.solver.eqExpr(espvar[0], self.solver.constExpr(0)))
        
        tmp = self.solver.UConstFromExpr(self.solver.simplify(self.regs["ESP"]))
        
        if espvar != False:
            self.solver.pop()
        
        if tmp != None:
            if tmp > 0x7fffffff: #negative value
                tmp = (-tmp) % (1<<32)
            complexity += tmp // 4 #[5]
        
        if flagProps:
            complexity += 1 #[6]
        
        return complexity

    def push(self):
        """
        Save the state machine (included the Solver's state) so that we can come back to this point later.
        Returns the stackLevel where the state was saved.
        """
        
        #first save the state of the Solver
        self.solver.push()
        
        #now the VM state
        tosave = ( deepcopy(self.regs), deepcopy(self.flags), deepcopy(self.exceptions), deepcopy(self.memory.sources),\
                   deepcopy(self.memory.undefvalues), self.memory.copy(), self.EIP, deepcopy(self.callstack) )
        
        self.stack.append(tosave)
        return len(self.stack) - 1
    
    def pop(self):
        #first lets put the state of the Solver again as it was before
        self.solver.pop()
        
        #clean memory dict
        self.memory.clear()
        
        #now the VM
        ret = self.stack.pop()
        ( self.regs, self.flags, self.exceptions, self.memory.sources, self.memory.undefvalues, mem, self.EIP, self.callstack ) = ret
        
        #fix memory
        self.memory.update(mem)
        
        return ret
    
    def popto(self, stackLevel):
        while len(self.stack) > stackLevel:
            ret=self.pop()
        return ret

    def mergeState(self, statemachine):
        """
        merge a given state machine to the current one, using the current as a base for the new one.
        
        Example:
        currentEAX=2
        to-mergeEAX=EAX+2
        --------
        mergedEAX=4
        """
        
        #create our substitution dictionary
        sub={}
        for k,v in self.regs.iteritems():
            sub[k]=v
        for k,v in self.flags.iteritems():
            sub[k]=v
        
        undefmem = {}
        for k in statemachine.memory.undefvalues.keys():
            source=statemachine.memory.sources[k.replace("VAL","MEM")]
            key=statemachine.solver.simplify(statemachine.solver.loadExpr(source))
            relatedvars=statemachine.solver.getVarDependency(key, return_name=True)
            undefmem[k]=(relatedvars, source)
        
        #iterate over all the undefined memory blocks
        runagain=True
        while runagain:
            runagain=False
            for k in undefmem.keys():
                relatedvars=undefmem[k][0]
                source=undefmem[k][1]
                clean=True
            
                for tmp in relatedvars:
                    if not sub.has_key(tmp):
                        runagain=True
                        clean=False
                        break
                
                if clean: #we got a clean memory reference
                    newkey=self.solver.loadExpr(source, varsdict=sub) #substitute vars
                    sub[k]=self.memory[newkey] #add the new entry to the subs dict
                    undefmem.pop(k)
        
        #merge memory first
        for k,v in statemachine.memory.iteritems():
            source=statemachine.memory.sources[k]
            newkey=self.solver.loadExpr(source, varsdict=sub)
            
            value_dump = statemachine.solver.dumpExpr(v)
            newvalue = self.solver.simplify(self.solver.loadExpr(value_dump, varsdict=sub))
            
            self.memory[newkey] = newvalue
        
        #merge regs
        for k,v in statemachine.regs.iteritems():
            dump = statemachine.solver.dumpExpr(v)
            self.regs[k] = self.solver.simplify(self.solver.loadExpr(dump, varsdict=sub))
        
        #merge flags
        for k,v in statemachine.flags.iteritems():
            dump = statemachine.solver.dumpExpr(v)
            self.flags[k] = self.solver.simplify(self.solver.loadExpr(dump, varsdict=sub))
            
        #merge EIP
        dump = statemachine.solver.dumpExpr(statemachine.EIP)
        self.EIP = self.solver.simplify(self.solver.loadExpr(dump, varsdict=sub))
            
        #merge exceptions
        for k,v in statemachine.exceptions.iteritems():
            dump = statemachine.solver.dumpExpr(v)
            self.exceptions[k] = self.solver.simplify(self.solver.loadExpr(dump, varsdict=sub))
        
    
    def simplify(self):
        for key in self.regs.keys():
            self.regs[key] = self.solver.simplify(self.regs[key])
        for key in self.exceptions.keys():
            self.exceptions[key] = self.solver.simplify(self.exceptions[key])
        self.memory.simplify()
        self.EIP = self.solver.simplify(self.EIP)
    
    def prettify(self):
        """
        Transform all Solver Expression to PrettySolver Expression instances
        """
        
        if isinstance(self.solver, PrettySolver):
            return
        
        self.solver = PrettySolver(self.solver)
        
        for key in self.regs.keys():
            self.regs[key] = Expression(self.solver, self.regs[key])
        for key in self.flags.keys():
            self.flags[key] = Expression(self.solver, self.flags[key])
        for key in self.exceptions.keys():
            self.exceptions[key] = Expression(self.solver, self.exceptions[key])
        self.memory.prettify()
        self.EIP = Expression(self.solver, self.EIP)
        
    
    def printMemory(self, imm):
        imm.log("-----========= Memory Sources ==========------")
        for x,y in self.memory.sources.iteritems():
            imm.log("%s:%s"%(x,y))
            imm.log("Indexes    :%s"%(tuple(self.memory.getIndexes(x)), ))
        imm.log("-----======== Undefined Memory =========------")
        for x in self.memory.undefvalues:
            imm.log("%s:%s"%(x,self.memory.sources[x.replace("VAL","MEM")]))
        imm.log("-----============ Memory ===============------")
        for k in self.memory.keys():
            imm.log("%s:%s"%(self.solver.exprString(self.solver.loadExpr(self.memory.sources[k])),self.solver.exprString(self.memory[k])))
    
    def printRegisters(self, imm):
        imm.log("-----=========== Registers =============------")
        for k,v in self.regs.iteritems():
            tmp = self.solver.UConstFromExpr(v)
            if tmp != None:
                imm.log("%s:%08X:0x%x"%(k,self.solver.hashExpr(v),tmp))
            else:
                imm.log("%s:%08X:%s"%(k,self.solver.hashExpr(v),self.solver.exprString(v)))
        
        tmp = self.solver.UConstFromExpr(self.EIP)
        if tmp != None:
            imm.log("EIP:%08X:0x%x"%(self.solver.hashExpr(self.EIP),tmp), tmp)
        else:
            imm.log("EIP:%08X:%s"%(self.solver.hashExpr(self.EIP), self.solver.exprString(self.EIP)))
        imm.log("-----============= Flags ===============------")
        for k,v in self.flags.iteritems():
            imm.log("%s:%s"%(k,self.solver.exprString(v)))
        imm.log("-----========== Exceptions =============------")
        for k,v in self.exceptions.iteritems():
            imm.log("%s:%s"%(k,self.solver.exprString(v)))
        
    def printState(self, imm):
        imm.log("******************************** Dumping state ******************************")
        self.printRegisters(imm)
        self.printMemory(imm)
        props=self.calcProperties()
        compexity=self.calcComplexity(props[0], props[1])
        imm.log("************ Properties *************")
        for k,v in props[0].iteritems():
            imm.log("%s=%s"%(k,self.regMapToTuple(v)))
        imm.log("FLAGS=%s"%self.flagMapToTuple(props[1]))
        imm.log("Complexity=%d"%compexity)

        if (len(self.callstack) > 0):
            imm.log("************ Callstack *************")
            for x in self.callstack:
                imm.log("Caller=0x%08x, Callee=0x%08x"%(x[0], x[1]), x[0])

class SequenceAnalyzer:
    def __init__(self, imm, r_model=None, f_model=None, m_model=False,
                 analysis_mods=[], simplifyState=True, queryTimeout=0, prettysolver=False):
        """
        @type r_model: Dict
        @param r_model: A dictionary mapping registers to concrete 
            values. Any registers not described in this dict will
            be described as undefined to the solver which effectively
            implies they are entirely user controlled and can 
            therefore be assigned any value by the solver when looking
            for a satisfying assignment

        @type f_model: Dict
        @param f_model: A dictionary mapping flags to concrete 
            values. Any flags not described in this dict will
            be described as undefined to the solver which effectively
            implies they are entirely user controlled and can 
            therefore be assigned any value by the solver when looking
            for a satisfying assignment
        
        @type m_model: Bool
        @param m_model: If this is set to True then the solver will use
            the current memory state of the process as the model for 
            any memory references it encounters during analysis. If it
            is False then values read from memory will be undefined
            initially. 
        """

        self.imm = imm
        self._debug = False
        self._traceback = False
        self.continue_on_error = False
        self.ignoredExceptions = []
        self.errors = []
        self.stack = []
        self.REPtooLongCounter=0x20 #a REP with a counter bigger than this is going to raise a "TooBigRepeatCounterException" exception

        self.useCurrentMemory = m_model
        
        sol = Solver(manualInitialization=True)
        sol.flags = sol.createFlags()
        sol.setIntFlag(sol.flags, "stimeout", queryTimeout)  #set a query timeout to avoid lockouts
                                                              #0 means unlimited
        sol.createValidityChecker(sol.flags)
        
        if prettysolver:
            sol = PrettySolver(sol)
        
        self.state = StateMachine(r_model, f_model, sol)

        #we do lazy updates for flags
        self.state.flags.updatecallback = self.updateFlagsReal

        # Analysis functions. Should support a check_ins function
        # that takes a SequenceAnalyzer object as its first argument and
        # an opCode object representing the current instruction as its
        # second argument. If it has anything to report it should return
        # an AnalysisResult object or None otherwise
        self.analysis_mods = analysis_mods

        # The analyzeNext function will call each analysis module on
        # each instruction *before* updating the state with the SMT
        # semantics of that instruction. 
        self.analysis_mod_results = {}
        
        for f in self.analysis_mods:
            self.analysis_mod_results[f] = []
            
        self.visitedAddresses = []
        self.initialAddress=None
        self.depth=None
        self.stopInstruction=None
        self.stopEIP=None
        self.lastAddress=None
        self.lastCmd=None
        self.simplifyState=simplifyState #simplify the state machine after each instruction

    def getAnalysisResults(self, checker=None):
        """
        If checker is not None then we return the list of results for
        the given checker or None if that checker isn't valid.

        If checker is None then we simply return the entire analysis
        results dictionary mapping checkers to result lists.
        """

        ret = None
        
        if checker is not None:
            if checker in self.analysis_mod_results:                
                ret = self.analysis_mod_results[checker]
            else:
                ret = None
        else:
            ret = self.analysis_mod_results

        return ret
            
    def push(self):
        """
        Save the entire state of the analyzer (included the Solver's state) so that we can come back to this point later.
        Returns the stackLevel where the state was saved.
        """
        
        #save the state of the VM
        self.state.push()
        
        #now the analyzer state
        tosave = ( copy(self.errors), self.initialAddress, self.depth, self.stopInstruction, self.stopEIP, copy(self.visitedAddresses), \
                   self.lastAddress, self.lastCmd)
        
        self.stack.append(tosave)
        return len(self.stack) - 1
    
    def pop(self):
        #first return the VM to the prior state
        self.state.pop()
        
        #now the analyzer
        ret = self.stack.pop()
        ( self.errors, self.initialAddress, self.depth, self.stopInstruction, self.stopEIP, self.visitedAddresses, self.lastAddress, \
          self.lastCmd) = ret
        
        return ret
    
    def popto(self, stackLevel):
        while len(self.stack) > stackLevel:
            ret=self.pop()
        return ret
    
    def makeClean(self, notused32bits, notusedbool):
        regs = {}
        flags = {}
        exceptions = {}
        for k in self.state.regs.keys():
            regs[k] = notused32bits
        for k in self.state.flags.keys():
            flags[k] = notusedbool
        for k in self.state.exceptions.keys():
            exceptions[k] = notusedbool
        return (regs, flags, exceptions, {}, {}, {}, notused32bits, notused32bits)
    
    def reportError(self, errortype, msg=""):
        if errortype.__name__.lower() in map(string.lower, self.ignoredExceptions):
            return
        
        if self._debug:
            self.imm.log("Exception %s: %s"%(errortype.__name__, msg))
            if self._traceback:
                self.imm.log("Traceback:")
                
                
                for line in traceback.extract_stack():
                    f_name = line[0]
                    line_num = line[1]
                    function = line[2]
                    src_line = line[3]
                    if function == "reportError":
                        continue
                    self.imm.log("File %s:%d" % (f_name, line_num))
                    self.imm.log("    Function: %s" % function)
                    self.imm.log("    Code: %s" % src_line)
        self.errors.append( (errortype.__name__, msg) )
        
        if not self.continue_on_error:
            raise errortype, msg
    
    def solveEIP(self, initialaddress=None):
        if initialaddress == None:
            initialaddress = self.initialAddress
        
        eip=self.state.solver.lookupVar("EIP")[0]
        self.state.solver.push()
        #we have to remove that assertion to maintain EIP relative
        self.state.solver.assertFormula(self.state.solver.eqExpr(eip, self.state.solver.constExpr(initialaddress)))
        simplified = self.state.solver.simplify(self.state.EIP)
        address=self.state.solver.UConstFromExpr(simplified)
        if address == None:
            self.state.solver.pop()
            #Don't know how to solve EIP
            self.reportError(UndefinedIPException, simplified)
            return None
        self.state.solver.pop()
        return address

    ####################### Command's decoding ###########################
    def analyze(self, initialaddress=None, depth=None, stopinstruction=None, stopEIP=None):
        """
        Analyze instructions from <initialaddress> until: <depth> is reached, <stopinstruction> is found or <stopEIP> is met.
        This is just a wrapper over analyzeNext().
        
        Returns False if there was some problem with the analysis (use self.errors to retrieve some explanations) or True if not.
        """
        
        if initialaddress: self.initialAddress=initialaddress
        if depth: self.depth=depth
        if stopinstruction: self.stopInstruction=stopinstruction
        if stopEIP: self.stopEIP=stopEIP
        steps=0
        
        while True:
            steps+=1
            try:
                ret = self.analyzeNext()
                if not ret:
                    return False
            except ConditionalJumpException:
                #we processed a conditional jump, stop here
                break
            except:
                #some exception arised, use self.errors to retrieve the information
                return False
            
            if self.stopEIP and self.lastAddress == self.stopEIP:
                break

            if self.stopInstruction and self.lastCmd == self.stopInstruction:
                break
            
            if self.depth and steps == self.depth:
                break
            
            if self.simplifyState == True:
                self.state.simplify()
                
        #simplify registers after all opcodes execution
        if self.simplifyState == True:
            self.state.simplify()
        return True
    
    def analyzeNext(self):
        address = self.solveEIP()
        if address == None:
            return False #we cant continue if we dont have a valid EIP
        
        if not self.imm.validateAddress(address, "X"):
            #EIP is at a non-executable mempage
            self.reportError(IPNonExecutablePageException, address)
        
        op = operations.operation(self.imm.disasm(address, DISASM_FILE)) #abstraction - skylar
        if not op.validateInstruction():
            self.reportError(InvalidInstructionException, op.getAddress())
            return True #we cant analyze an invalid instruction, so we move to the next one
        
        if address in self.visitedAddresses:
            self.reportError(LoopDetectedException, op.getAddress())
        else:
            self.visitedAddresses.append(address)
        
        if self._debug: self.imm.log("Analyzing '%s'"%op.getDisasm(),op.getAddress())
        self.state.EIP = self.state.solver.simplify(self.state.solver.addExpr(self.state.EIP, self.state.solver.constExpr(op.getSize())))
        cmd = op.removeLockPrefix()

        for f in self.analysis_mods:
            self.push()
            res = f.checkIns(self, op)
            self.pop()
            
            if res is not None:
                self.analysis_mod_results[f].append(res)
                
        self.lastCmd=cmd
        self.lastDisasm=op.getDisasm()
        self.lastAddress=address
        
        if cmd == 'NOP':
            return True
        if hasattr(self, "analyze%s"%cmd):
            getattr(self, "analyze%s"%cmd)(op)
        else:
            if not self.analyzeAllUnsupported(op, cmd):
                self.reportError(UnsupportedOpcodeException, self.lastAddress)

        ex = self.checkExceptions()
        if ex:
            self.reportError(ProcessorException, (ex, self.lastAddress))
        
        return True
    
    def checkExceptions(self):
        """
        Only stop if we are sure that an exception arised
        """
        
        for name,expr in self.state.exceptions.iteritems():
            if self.state.solver.simplify(expr) == "TRUE": #VALID TRUE
                return name
        
        return None
    
    def analyzeAllUnsupported(self, op, cmd):
        #we could add all the FPU/MMX/SSE2,3/etc instructions that dont touch the registers/mem/flags/exceptions
        if cmd == "WAIT":
            return True
        
        return False
    
    def __REPHelper(self, op):
        simplified=self.state.solver.simplify(self.state.regs["ECX"])
        counter = self.state.solver.UConstFromExpr(simplified)
        if counter == None:
            #We cannot emulate a REP/REPNE if ECX is not completely defined
            self.reportError(UndefinedRepeatCounterException, simplified)
        
        if counter > self.REPtooLongCounter:
            #This instruction is going to take too long to be emulated
            self.reportError(TooBigRepeatCounterException, counter)
        
        cmd=op.getDisasm().upper().replace("LOCK ","").split(' ')[1]
        
        return (counter, cmd)
        
    def analyzeREP(self, op):
        """
        It stops on Counter == 0
        MOVS, LODS and STOS
        """
        
        (counter, cmd) = self.__REPHelper(op)
        
        for x in xrange(counter-1, -1, -1):
            getattr(self, "analyze%s"%cmd)(op)
            self.state.regs["ECX"]=self.state.solver.constExpr(x)
    
    def __analyzeREPcc(self, op, zf):
        (counter, cmd) = self.__REPHelper(op)
        if cmd not in ('CMPS', 'SCAS'):
            #for some reason, you can use the REPNE prefix with a non-comparative string operation
            self.analyzeREP(op)
            return
        
        states=[]
        for x in xrange(counter-1, -1, -1):
            getattr(self, "analyze%s"%cmd)(op)
            #this instruction changes ESI (if CMPS), EDI, ECX, OF, SF, ZF, AF, PF, and CF
            
            if x > 0:
                tmp = {"EDI":self.state.regs["EDI"], "ECX":self.state.solver.constExpr(x), \
                                "_OF":self.state.flags["_OF"], "_SF":self.state.flags["_SF"], \
                                "_ZF":self.state.flags["_ZF"], "_AF":self.state.flags["_AF"], \
                                "_PF":self.state.flags["_PF"], "_CF":self.state.flags["_CF"]}
                if cmd == "CMPS":
                    tmp["ESI"]=self.state.regs["ESI"]                    
                states.append( tmp )
        
        self.state.regs["ECX"]=self.state.solver.constExpr(0)
        while states:
            state=states.pop()
            ifclause = state["_ZF"]
            if zf == 0:
                ifclause = self.state.solver.boolNotExpr(ifclause)
                
            for k,v in state.iteritems():
                if "_" in k:
                    self.state.flags[k] = self.state.solver.iteExpr(ifclause, v, self.state.flags[k])
                else:
                    self.state.regs[k] = self.state.solver.iteExpr(ifclause, v, self.state.regs[k])
            
    def analyzeREPE(self, op):
        """
        It stops on Counter == 0 or ZF = 0
        CMPS and SCAS
        """
        
        self.__analyzeREPcc(op, zf=0)
    
    def analyzeREPNE(self, op):
        """
        It stops on Counter == 0 or ZF = 1
        CMPS and SCAS
        """
        
        self.__analyzeREPcc(op, zf=1)
        
    def analyzeINT3(self, op):
        self.state.exceptions["#BP"]=self.state.solver.true
    
    def analyzeINTO(self, op):
        self.state.exceptions["#OF"]=self.state.flags["_OF"]
        
    def analyzeRETN(self, op):
        if len(self.state.callstack):
            self.state.callstack.pop()
        self.state.EIP = self.getMemoryStateFromSolverState(self.state.regs['ESP'], 32)
        self.state.regs['ESP'] = self.state.solver.addExpr(self.state.regs['ESP'], self.state.solver.addExpr(self.state.solver.constExpr(4), self.state.solver.constExpr(op.op1Constant())))
    
    def analyzeLEA(self, op):
        dst = self.buildState(op, 0)
        
        #IDBUG: for some reason this doesn't get set originally
        if op.op2Size() == 2:
            op.operand[1] = (DEC_WORD,op.op2Size(),op.op2Register(),op.op2Constant())
        else:
            op.operand[1] = (DEC_DWORD,op.op2Size(),op.op2Register(),op.op2Constant())
        src = self.buildState(op, 1)
        value = self.transformMemoryStateToSolverState(src[0])
        
        dstreg = Registers32BitsOrder[dst[0][1]]
        self.state.regs[dstreg] = self.state.solver.assignExpr(self.state.regs[dstreg], value, dst[1])
    
    def analyzeINC(self, op):
        #make a fake ADD <whatever>, 1
        #CF is not updated by INC
        cf = self.state.flags['_CF']
        op.operand = ( op.operand[0], op.constantOperand(1), op.emptyOperand() )
        self.analyzeADD(op)
        self.state.flags['_CF'] = cf
        
    def analyzeDEC(self, op):
        #make a fake SUB <whatever>, 1
        #CF is not updated by DEC
        cf = self.state.flags['_CF']
        op.operand = ( op.operand[0], op.constantOperand(1), op.emptyOperand() )
        self.analyzeSUB(op)
        self.state.flags['_CF'] = cf
    
    def analyzeMOV(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        srcvalue = self.getValueFromState(src)
        srcvalue = self.fixOP2(srcvalue, dst[1])        
        self.setValueFromState(dst, srcvalue)
    
    def analyzeCMOVcc(self, op, cond):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        srcvalue = self.getValueFromState(src)
        srcvalue = self.fixOP2(srcvalue, dst[1])        
        dstvalue = self.getValueFromState(dst)
        newval = self.state.solver.iteExpr(cond, srcvalue, dstvalue)
        self.setValueFromState(dst, newval)

    def analyzeCMOVO(self, op):
        cond=self.state.flags["_OF"]
        self.analyzeCMOVcc(op, cond)
        
    def analyzeCMOVNO(self, op):
        cond=self.state.solver.boolNotExpr(self.state.flags["_OF"])
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVB(self, op):
        cond=self.state.flags["_CF"]
        self.analyzeCMOVcc(op, cond)
        
    def analyzeCMOVNB(self, op):
        cond=self.state.solver.boolNotExpr(self.state.flags["_CF"])
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVE(self, op):
        cond=self.state.flags["_ZF"]
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVNZ(self, op):
        cond=self.state.solver.boolNotExpr(self.state.flags["_ZF"])
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVBE(self, op):
        cond=self.state.solver.boolOrExpr(self.state.flags["_CF"], self.state.flags["_ZF"])
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVA(self, op):
        cond=self.state.solver.boolAndExpr(self.state.solver.boolNotExpr(self.state.flags["_CF"]), self.state.solver.boolNotExpr(self.state.flags["_ZF"]))
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVS(self, op):
        cond=self.state.flags["_SF"]
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVNS(self, op):
        cond=self.state.solver.boolNotExpr(self.state.flags["_SF"])
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVPE(self, op):
        cond=self.state.flags["_PF"]
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVPO(self, op):
        cond=self.state.solver.boolNotExpr(self.state.flags["_PF"])
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVL(self, op):
        cond=self.state.solver.iffExpr(self.state.flags["_SF"], self.state.solver.boolNotExpr(self.state.flags["_OF"]))
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVGE(self, op):
        cond=self.state.solver.iffExpr(self.state.flags["_SF"], self.state.flags["_OF"])
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVLE(self, op):
        cond=self.state.solver.boolOrExpr(self.state.flags["_ZF"], self.state.solver.iffExpr(self.state.flags["_SF"], self.state.solver.boolNotExpr(self.state.flags["_OF"])))
        self.analyzeCMOVcc(op, cond)
    
    def analyzeCMOVG(self, op):
        cond=self.state.solver.boolAndExpr(self.state.solver.boolNotExpr(self.state.flags["_ZF"]), self.state.solver.iffExpr(self.state.flags["_SF"], self.state.flags["_OF"]))
        self.analyzeCMOVcc(op, cond)
        
    def analyzeMOVS(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        srcvalue = self.getValueFromState(src)
        self.setValueFromState(dst, srcvalue)
        self.state.regs["ESI"]=self.state.solver.iteExpr(self.state.flags["_DF"], 
        self.state.solver.subExpr(self.state.regs["ESI"], self.state.solver.constExpr(op.op1Size(), 32)),
        self.state.solver.addExpr(self.state.regs["ESI"], self.state.solver.constExpr(op.op1Size(), 32)))
        self.state.regs["EDI"]=self.state.solver.iteExpr(self.state.flags["_DF"], 
        self.state.solver.subExpr(self.state.regs["EDI"], self.state.solver.constExpr(op.op1Size(), 32)),
        self.state.solver.addExpr(self.state.regs["EDI"], self.state.solver.constExpr(op.op1Size(), 32)))
    
    def analyzeSUB(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        (res,dstval,srcval)=self.solveArithmetic(self.state.solver.subExpr,dst,src)
        self.updateFlags("SUB", res, dstval, srcval)
        
    def analyzeSBB(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        tmp = ( ( 'flag', '_CF' ), dst[1] )
        (notused,dstval,srcval)=self.solveArithmetic(self.state.solver.subExpr,dst,src)
        (res,notused,notused)  =self.solveArithmetic(self.state.solver.subExpr,dst,tmp)
        self.updateFlags("SBB", res, dstval, srcval)
    
    def analyzeADD(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        (res,dstval,srcval)=self.solveArithmetic(self.state.solver.addExpr,dst,src)
        self.updateFlags("ADD", res, dstval, srcval)
    
    def analyzeADC(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        tmp = ( ( 'flag', '_CF' ), dst[1] )
        (notused,dstval,srcval)=self.solveArithmetic(self.state.solver.addExpr,dst,src)
        (res,notused,notused)  =self.solveArithmetic(self.state.solver.addExpr,dst,tmp)
        self.updateFlags("ADC", res, dstval, srcval)
        
    def analyzeXOR(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        (res,dstval,srcval)=self.solveArithmetic(self.state.solver.xorExpr,dst,src)
        self.updateFlags("LOGIC", res, dstval, srcval)
        
    def analyzeAND(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        (res,dstval,srcval)=self.solveArithmetic(self.state.solver.andExpr,dst,src)
        self.updateFlags("LOGIC", res, dstval, srcval)
        
    def analyzeOR(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        (res,dstval,srcval)=self.solveArithmetic(self.state.solver.orExpr,dst,src)
        self.updateFlags("LOGIC", res, dstval, srcval)
        
    def analyzeNOT(self, op):
        dst = self.buildState(op, 0)
        self.solveArithmetic(self.state.solver.notExpr,dst)
        
    def analyzeSHR(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        (res,dstval,srcval)=self.solveArithmetic(self.state.solver.rightShiftExpr,dst,src)
        self.updateFlags("SHR", res, dstval, srcval)
        
    def analyzeSAR(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        (res,dstval,srcval)=self.solveArithmetic(self.state.solver.rightArithmeticShiftExpr,dst,src)
        self.updateFlags("SAR", res, dstval, srcval)
    
    def analyzeSHRD(self, op):
        op1 = self.buildState(op, 0)
        op2 = self.buildState(op, 1)
        op3 = self.buildState(op, 2)
        op1val = self.getValueFromState(op1)
        op2val = self.getValueFromState(op2)
        op3val = self.getValueFromState(op3)
        finalsize=op1[1]
        
        bits_size=op3[1]
        bits=self.state.solver.andExpr(op3val,self.state.solver.constExpr(31, bits_size))
        
        for count in range(finalsize, -1, -1):
            if count != finalsize:
                ifpart = self.state.solver.eqExpr(bits, self.state.solver.constExpr(count, op3[1]))
                if count:
                    #count=[1:31]
                    tmp1 = self.state.solver.extractExpr(op2val, 0, count-1)
                    tmp2 = self.state.solver.extractExpr(op1val, count, finalsize-1)
                    thenpart = self.state.solver.concatExpr(tmp1, tmp2)
                else:
                    #count=0
                    thenpart = op1val
                ite = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
                elsepart = ite
            else:
                #count=32
                elsepart = op2val
        
        self.setValueFromState(op1, ite)
        self.updateFlags("SHRD", ite, op1val, op3val) #put counter in second position as a normal SHR

    def analyzeSAL(self, op):
        self.analyzeSHL(op)
    
    def analyzeSHL(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        (res,dstval,srcval)=self.solveArithmetic(self.state.solver.leftShiftExpr,dst,src)
        self.updateFlags("SHL", res, dstval, srcval)
    
    def analyzeSHLD(self, op):
        op1 = self.buildState(op, 0)
        op2 = self.buildState(op, 1)
        op3 = self.buildState(op, 2)
        op1val = self.getValueFromState(op1)
        op2val = self.getValueFromState(op2)
        op3val = self.getValueFromState(op3)
        finalsize=op1[1]
        
        bits_size=op3[1]
        bits=self.state.solver.andExpr(op3val,self.state.solver.constExpr(31, bits_size))
        
        for count in range(finalsize, -1, -1):
            if count != finalsize:
                ifpart = self.state.solver.eqExpr(bits, self.state.solver.constExpr(count, op3[1]))
                if count:
                    #count=[1:31]
                    tmp1 = self.state.solver.extractExpr(op1val, 0, finalsize-count-1)
                    tmp2 = self.state.solver.extractExpr(op2val, finalsize-count, finalsize-1)
                    thenpart = self.state.solver.concatExpr(tmp1, tmp2)
                else:
                    #count=0
                    thenpart = op1val
                ite = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
                elsepart = ite
            else:
                #count=32
                elsepart = op2val
        
        self.setValueFromState(op1, ite)
        self.updateFlags("SHLD", ite, op1val, op3val) #put counter in second position as a normal SHL
    
    def analyzeNEG(self, op):
        dst = self.buildState(op, 0)
        (res,dstval,notused)=self.solveArithmetic(self.state.solver.negExpr,dst)
        self.updateFlags("NEG", res, dstval)
        
    def analyzeRCL(self, op):
        """
        We handle CF here, not in updateFlags and do the solveArithmetic manually to handle 33bits operations
        """
        dst = self.buildState(op, 0); dstvalue = self.getValueFromState(dst)
        src = self.buildState(op, 1); srcvalue = self.getValueFromState(src)
        srcvalue = self.fixOP2(srcvalue, dst[1])
        srcsize = self.state.solver.getBitSizeFromExpr(srcvalue)
        
        #all rotates are constrained to <= 31 bits
        srcvalue = self.state.solver.andExpr(srcvalue, self.state.solver.constExpr(0x1f, srcsize))

        tmp = self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_CF"]), dstvalue)
        res = self.state.solver.leftRotateExpr(tmp, srcvalue)
        
        self.setValueFromState(dst, self.state.solver.extractExpr(res, 0, dst[1]-1))
        self.updateFlags("RCL", res, dstvalue, srcvalue)
    
    def analyzeROL(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        (res,dstval,srcval)=self.solveArithmetic(self.state.solver.leftRotateExpr,dst,src)
        self.updateFlags("ROL", res, dstval, srcval)
        
    def analyzeROR(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        (res,dstval,srcval)=self.solveArithmetic(self.state.solver.rightRotateExpr,dst,src)
        self.updateFlags("ROR", res, dstval, srcval)
    
    def analyzeRCR(self, op):
        """
        We handle CF here, not in updateFlags and do the solveArithmetic manually to handle 33bits operations
        """
        dst = self.buildState(op, 0); dstvalue = self.getValueFromState(dst)
        src = self.buildState(op, 1); srcvalue = self.getValueFromState(src)
        srcvalue = self.fixOP2(srcvalue, dst[1])
        srcsize = self.state.solver.getBitSizeFromExpr(srcvalue)
        
        #all rotates are constrained to <= 31 bits
        srcvalue = self.state.solver.andExpr(srcvalue, self.state.solver.constExpr(0x1f, srcsize))

        tmp = self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_CF"]), dstvalue)
        res = self.state.solver.rightRotateExpr(tmp, srcvalue)
        
        self.setValueFromState(dst, self.state.solver.extractExpr(res, 0, dst[1]-1))
        self.updateFlags("RCR", res, dstvalue, srcvalue)
    
    def analyzePUSHAD(self, op):
        temp = self.state.regs["ESP"]
        op.operand = [op.registerOperand('EAX'),op.emptyOperand(),op.emptyOperand()]; self.analyzePUSH(op) #EAX
        op.operand = [op.registerOperand('ECX'),op.emptyOperand(),op.emptyOperand()]; self.analyzePUSH(op) #ECX
        op.operand = [op.registerOperand('EDX'),op.emptyOperand(),op.emptyOperand()]; self.analyzePUSH(op) #EDX
        op.operand = [op.registerOperand('EBX'),op.emptyOperand(),op.emptyOperand()]; self.analyzePUSH(op) #EBX
        
        #ESP
        self.state.regs['ESP'] = self.state.solver.subExpr(self.state.regs['ESP'], self.state.solver.constExpr(4))
        mem_index = [ [ 'mem', ['ESP', 1, self.state.regs['ESP'], '', 0, [], 0] ], 32 ]
        self.setMemoryState(mem_index, temp)
        
        op.operand = [op.registerOperand('EBP'),op.emptyOperand(),op.emptyOperand()]; self.analyzePUSH(op) #EBP
        op.operand = [op.registerOperand('ESI'),op.emptyOperand(),op.emptyOperand()]; self.analyzePUSH(op) #ESI
        op.operand = [op.registerOperand('EDI'),op.emptyOperand(),op.emptyOperand()]; self.analyzePUSH(op) #EDI
        
    def analyzePUSH(self, op):
        src = self.buildState(op, 0)
        size = src[1]

        value = self.getValueFromState(src)
        
        self.state.regs['ESP'] = self.state.solver.subExpr(self.state.regs['ESP'], self.state.solver.constExpr(4))
        mem_index = [ [ 'mem', ['ESP', 1, self.state.regs['ESP'], '', 0, [], 0] ], size ]
        self.setMemoryState(mem_index, value)
        
    def analyzePOPAD(self, op):
        op.operand = [op.registerOperand('EDI'),op.emptyOperand(),op.emptyOperand()]; self.analyzePOP(op) #EDI
        op.operand = [op.registerOperand('ESI'),op.emptyOperand(),op.emptyOperand()]; self.analyzePOP(op) #ESI
        op.operand = [op.registerOperand('EBP'),op.emptyOperand(),op.emptyOperand()]; self.analyzePOP(op) #EBP
        self.state.regs['ESP'] = self.state.solver.addExpr(self.state.regs['ESP'], self.state.solver.constExpr(4)) #SKIP ESP
        op.operand = [op.registerOperand('EBX'),op.emptyOperand(),op.emptyOperand()]; self.analyzePOP(op) #EBX
        op.operand = [op.registerOperand('EDX'),op.emptyOperand(),op.emptyOperand()]; self.analyzePOP(op) #EDX
        op.operand = [op.registerOperand('ECX'),op.emptyOperand(),op.emptyOperand()]; self.analyzePOP(op) #ECX
        op.operand = [op.registerOperand('EAX'),op.emptyOperand(),op.emptyOperand()]; self.analyzePOP(op) #EAX
    
    def analyzePOP(self, op):
        mem_index = [ [ 'mem', ['ESP', 1, self.state.regs['ESP'], '', 0, [], 0] ], 32 ]
        value = self.getMemoryState(mem_index)
        self.state.regs['ESP'] = self.state.solver.addExpr(self.state.regs['ESP'], self.state.solver.constExpr(4))
        
        dst = self.buildState(op, 0)
        self.setValueFromState(dst, value)
    
    def analyzePOPFD(self, op):
        """    33222222222211111111110000000000
               10987654321098765432109876543210
               --------------------------------
        EFLAGS=0000000000IVVAVR0NIIODITSZ0A0P1C
                         DIICMF TOOFFFFFF F F F
                          PF     PP
                                 LL
        """
        mem_index = [ [ 'mem', ['ESP', 1, self.state.regs['ESP'], '', 0, [], 0] ], 32 ]
        value = self.getMemoryState(mem_index)
        self.state.regs['ESP'] = self.state.solver.addExpr(self.state.regs['ESP'], self.state.solver.constExpr(4))
        
        self.state.flags["_CF"]=self.state.solver.boolExtractExpr(value, 0)
        self.state.flags["_PF"]=self.state.solver.boolExtractExpr(value, 2)
        self.state.flags["_AF"]=self.state.solver.boolExtractExpr(value, 4)
        self.state.flags["_ZF"]=self.state.solver.boolExtractExpr(value, 6)
        self.state.flags["_SF"]=self.state.solver.boolExtractExpr(value, 7)
        self.state.flags["_DF"]=self.state.solver.boolExtractExpr(value, 10)
        self.state.flags["_OF"]=self.state.solver.boolExtractExpr(value, 11)
    
    def analyzePUSHFD(self, op):
        value = self.state.solver.concatExpr(self.state.solver.constExpr(0, 20), \
                                       self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_OF"]),\
                                       self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_DF"]),\
                                       self.state.solver.concatExpr(self.state.solver.constExpr(0, 2),\
                                       self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_SF"]),\
                                       self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_ZF"]),\
                                       self.state.solver.concatExpr(self.state.solver.constExpr(0, 1),\
                                       self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_AF"]),\
                                       self.state.solver.concatExpr(self.state.solver.constExpr(0, 1),\
                                       self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_PF"]),\
                                       self.state.solver.concatExpr(self.state.solver.constExpr(1, 1),\
                                       self.state.solver.getBitvectorFromBool(self.state.flags["_CF"])\
                                       )))))))))))
        
        self.state.regs['ESP'] = self.state.solver.subExpr(self.state.regs['ESP'], self.state.solver.constExpr(4))
        mem_index = [ [ 'mem', ['ESP', 1, self.state.regs['ESP'], '', 0, [], 0] ], 32 ]
        self.setMemoryState(mem_index, value)
    
    def analyzeLAHF(self, op):
        """
        AH = RFLAGS(SF:ZF:0:AF:0:PF:1:CF);
        """
        value =                        self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_SF"]),\
                                       self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_ZF"]),\
                                       self.state.solver.concatExpr(self.state.solver.constExpr(0, 1),\
                                       self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_AF"]),\
                                       self.state.solver.concatExpr(self.state.solver.constExpr(0, 1),\
                                       self.state.solver.concatExpr(self.state.solver.getBitvectorFromBool(self.state.flags["_PF"]),\
                                       self.state.solver.concatExpr(self.state.solver.constExpr(1, 1),\
                                       self.state.solver.getBitvectorFromBool(self.state.flags["_CF"])\
                                       )))))))
        self.state.regs["EAX"]=self.state.solver.assignExpr(self.state.regs["EAX"], value, 8, 8)
        
    def analyzeSAHF(self, op):
        """
        FLAGS(SF:ZF:0:AF:0:PF:1:CF) = AH
        """
    
        self.state.flags["_CF"]=self.state.solver.boolExtractExpr(self.state.regs["EAX"], 8+0)
        self.state.flags["_PF"]=self.state.solver.boolExtractExpr(self.state.regs["EAX"], 8+2)
        self.state.flags["_AF"]=self.state.solver.boolExtractExpr(self.state.regs["EAX"], 8+4)
        self.state.flags["_ZF"]=self.state.solver.boolExtractExpr(self.state.regs["EAX"], 8+6)
        self.state.flags["_SF"]=self.state.solver.boolExtractExpr(self.state.regs["EAX"], 8+7)
    
    def analyzeMOVZX(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        value = self.getValueFromState(src)
        
        #zero-extend to dst size
        value = self.state.solver.concatExpr(self.state.solver.constExpr(0, dst[1] - src[1]), value)
        self.setValueFromState(dst, value)
    
    def analyzeMOVSX(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        value = self.getValueFromState(src)
        
        #sign-extend to dst size
        value = self.state.solver.signExtendExpr(value, dst[1])
        self.setValueFromState(dst, value)
        
    def analyzeXCHG(self, op):
        if op.operand[0] == op.operand[1]:
            #this is a NO-OP
            return True
        
        #get both variables
        var1 = self.buildState(op, 0)
        value1 = self.getValueFromState(var1)
        
        var2 = self.buildState(op, 1)
        value2 = self.getValueFromState(var2)
        
        #EXCHANGE!
        self.setValueFromState(var1, value2)
        self.setValueFromState(var2, value1)
    
    def analyzeENTER(self, op):
        op1 = self.buildState(op, 0)
        op2 = self.buildState(op, 1)
        size = op1[0][1]
        nestingLevel = op2[0][1] % 32 #MOD 32
        
        op.operand = [op.registerOperand('EBP'), op.emptyOperand(), op.emptyOperand()] #PUSH EBP
        self.analyzePUSH(op)
        frameTemp = self.state.regs["ESP"]
        
        if nestingLevel:
            for x in range(0, nestingLevel-1):
                self.state.regs["EBP"] = self.state.solver.subExpr(self.state.regs["EBP"], self.state.solver.constExpr(4, 32))
                op.operand = [op.memoryOperand('EBP'), op.emptyOperand(), op.emptyOperand()] #PUSH [EBP]
                self.analyzePUSH(op)
                    
            #PUSH frameTemp
            self.state.regs['ESP'] = self.state.solver.subExpr(self.state.regs['ESP'], self.state.solver.constExpr(4))
            mem_index = [ [ 'mem', ['ESP', 1, self.state.regs['ESP'], '', 0, [], 0] ], 32 ]
            self.setMemoryState(mem_index, frameTemp)

        self.state.regs["EBP"] = frameTemp #MOV EBP, frameTemp
        self.state.regs["ESP"] = self.state.solver.subExpr(self.state.regs["ESP"], self.state.solver.constExpr(size, 32))

    def analyzeLEAVE(self, op):
        self.state.regs["ESP"] = self.state.regs["EBP"] #MOV ESP, EBP
        op.operand = [op.registerOperand('EBP'), op.emptyOperand(), op.emptyOperand()] #POP EBP
        self.analyzePOP(op)
    
    def analyzeSALC(self, op):
        ifpart = self.state.flags["_CF"]
        thenpart = self.state.solver.constExpr(0xff, bits=8)
        elsepart = self.state.solver.constExpr(0, bits=8)
        res = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], res, bits=8)

    def analyzeAAA(self, op):
        """
        Logic for this instruction:
        IF ((AL AND 0FH) > 9) OR (AF = 1)
        THEN
        AL = (AL + 6);
        AH = AH + 1;
        AF = 1;
        CF = 1;
        ELSE
        AF = 0;
        CF = 0;
        FI;
        AL = AL AND 0FH;
        """
        
        exprAL = self.state.solver.extractExpr(self.state.regs['EAX'], 0, 7) 
        exprAH = self.state.solver.extractExpr(self.state.regs['EAX'], 8, 15) 
        
        #IF
        expr0 = self.state.solver.extractExpr(exprAL, 0, 3) #AL & 0xf
        expr1 = self.state.solver.gtExpr(expr0, self.state.solver.constExpr(9, bits=4)) #expr0 is 4 bits long, so the second part of the comparison must be 4 too
        ifpart = self.state.solver.boolOrExpr(expr1, self.state.flags['_AF'])

        #THEN
        expr2 = self.state.solver.addExpr(exprAL, self.state.solver.constExpr(6, bits=8)) #AL+6
        expr3 = self.state.solver.addExpr(exprAH, self.state.solver.constExpr(1, bits=8)) #AH+1
        thenpart = self.state.solver.concatExpr(expr3, expr2)

        #ELSE
        elsepart = self.state.solver.concatExpr(exprAH, exprAL)

        expr4 = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        newAL = self.state.solver.andExpr(self.state.solver.extractExpr(expr4, 0, 7), self.state.solver.constExpr(0xf, 8)) #AL & 0xf
        newAX = self.state.solver.assignExpr(expr4, newAL, bits=8)
        
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], newAX, 16)
        
        self.state.flags['_AF']=ifpart
        self.state.flags['_CF']=ifpart

    def analyzeAAS(self, op):
        """Logic:
        Same as AAA except thenpart will have
        AL = AL - 6;
        AH = AH - 1;
        instead of +6 and +1
        """
        exprAL = self.state.solver.extractExpr(self.state.regs['EAX'], 0, 7) 
        exprAH = self.state.solver.extractExpr(self.state.regs['EAX'], 8, 15) 
        
        #IF
        expr0 = self.state.solver.extractExpr(exprAL, 0, 3) #AL & 0xf
        expr1 = self.state.solver.gtExpr(expr0, self.state.solver.constExpr(9, bits=4)) #expr0 is 4 bits long, so the second part of the comparison must be 4 too
        ifpart = self.state.solver.boolOrExpr(expr1, self.state.flags['_AF'])

        #THEN
        expr2 = self.state.solver.subExpr(exprAL, self.state.solver.constExpr(6, bits=8)) #AL-6
        expr3 = self.state.solver.subExpr(exprAH, self.state.solver.constExpr(1, bits=8)) #AH-1
        thenpart = self.state.solver.concatExpr(expr3, expr2)

        #ELSE
        elsepart = self.state.solver.concatExpr(exprAH, exprAL)

        expr4 = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        newAL = self.state.solver.andExpr(self.state.solver.extractExpr(expr4, 0, 7), self.state.solver.constExpr(0xf, 8)) #AL & 0xf
        newAX = self.state.solver.assignExpr(expr4, newAL, bits=8)
        
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], newAX, 16)
        
        self.state.flags['_AF']=ifpart
        self.state.flags['_CF']=ifpart
        
    def analyzeAAM(self, op):
        """Logic:
        AH = AL/base
        AL = AL mod base
        """
        exprAL = self.state.solver.extractExpr(self.state.regs['EAX'], 0, 7)
        baseval = self.state.solver.constExpr(int(op.dump[2:], 16), 8) #IDBUG: unfortunately ID doesn't give us the base as an operand, so we extract it from the instruction dump
        newAH = self.state.solver.udivExpr(exprAL, baseval)
        newAL = self.state.solver.uremExpr(exprAL, baseval)
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], newAH, bits=8, endpos=8) #set AH
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], newAL, bits=8) #set AL
        #update flags based on resulting AL
        self.updateFlags("AAM", newAL, newAL) 
        
    def analyzeAAD(self, op):
        """
        Logic:
        AL = AL + AH*base
        AH = 0
        """
        exprAL = self.state.solver.extractExpr(self.state.regs['EAX'], 0, 7) 
        exprAH = self.state.solver.extractExpr(self.state.regs['EAX'], 8, 15)
        
        baseval = self.state.solver.constExpr(int(op.dump[2:], 16), 8) #IDBUG: unfortunately ID doesn't give us the base as an operand, so we extract it from the instruction dump
        
        expr0 = self.state.solver.umulExpr(exprAH, baseval) #unsigned multiplication
        newAL = self.state.solver.addExpr(exprAL, expr0)
        
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], self.state.solver.constExpr(0), bits=8, endpos=8) #set AH
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], newAL, bits=8) #set AL
        #update flags based on resulting AL
        self.updateFlags("AAD", newAL, newAL) 
    
    def analyzeBSF(self,op):
        """Logic:
        IF SRC == 0
        THEN
        ZF = 1;
        DEST is undefined;
        ELSE
        ZF = 0;
        temp = 0;
        WHILE Bit(SRC, temp) == 0
        DO
        temp = temp + 1;
        DEST = temp;
        OD;
        FI;
        
        In this cases, where the loops are constrained (no more that 32 iterations) we can unwind them into cascaded ITEs.
        See: rightShiftExpr/leftShiftExpr for an example.
        """
        
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        dstval = self.getValueFromState(dst)
        srcval = self.getValueFromState(src)
        
        for x in range(src[1],-1,-1):
            if x != src[1]:
                ifpart = self.state.solver.boolExtractExpr(srcval, x)
                thenpart = self.state.solver.constExpr(x, dst[1])
                ite = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
                elsepart = ite
            else:
                elsepart = dstval
        
        self.setValueFromState(dst, ite)
        
        self.updateFlags('BSF', srcval, srcval)
    
    def analyzeBSR(self,op):
        """
        Like BSF but reverse.
        """
        
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        dstval = self.getValueFromState(dst)
        srcval = self.getValueFromState(src)
        
        for x in range(-1, src[1]):
            if x != -1:
                ifpart = self.state.solver.boolExtractExpr(srcval, x)
                thenpart = self.state.solver.constExpr(x, dst[1])
                ite = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
                elsepart = ite
            else:
                elsepart = dstval
        
        self.setValueFromState(dst, ite)
        
        self.updateFlags('BSR', srcval, srcval)

    def analyzeBSWAP(self, op):
        """This will need to be updated for 64-bits"""
        src = self.buildState(op, 0)
        srcval = self.getValueFromState(src)
        #extract the byte values
        byte3 = self.state.solver.extractExpr(srcval, 0, 7)
        byte2 = self.state.solver.extractExpr(srcval, 8, 15)
        byte1 = self.state.solver.extractExpr(srcval, 16, 23)
        byte0 = self.state.solver.extractExpr(srcval, 24, 31)
        #put them back together in reverse order
        temp = self.state.solver.concatExpr(byte3, byte2)
        temp2 = self.state.solver.concatExpr(temp, byte1)
        newval = self.state.solver.concatExpr(temp2, byte0)
        self.setValueFromState(src, newval)
        
    def analyzeBT(self, op):
        """The destination bit indexed by the source value is copied into the Carry Flag."""
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        dstval = self.getValueFromState(dst)
        srcval = self.getValueFromState(src)
        srcval = self.fixOP2(srcval, dst[1])
        
        mask = self.state.solver.leftShiftExpr(self.state.solver.constExpr(1, dst[1]), srcval) #2^srcval
        res = self.state.solver.andExpr(dstval, mask)
        self.state.flags['_CF'] = self.state.solver.getBoolFromBitvector(res)
        
    def analyzeBTC(self, op):
        """The destination bit indexed by the source value is copied into the Carry Flag, then complemented and stored."""
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        dstval = self.getValueFromState(dst)
        srcval = self.getValueFromState(src)
        srcval = self.fixOP2(srcval, dst[1])
        
        mask = self.state.solver.leftShiftExpr(self.state.solver.constExpr(1, dst[1]), srcval) #2^srcval
        res = self.state.solver.andExpr(dstval, mask)
        self.updateFlags('BT', self.state.solver.getBoolFromBitvector(res))
        
        result = self.state.solver.xorExpr(dstval, mask) #complement the bit
        self.setValueFromState(dst, result)
        
    def analyzeBTR(self, op):
        """The destination bit indexed by the source value is copied into the Carry Flag and then cleared."""
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        dstval = self.getValueFromState(dst)
        srcval = self.getValueFromState(src)
        srcval = self.fixOP2(srcval, dst[1])
        
        mask = self.state.solver.leftShiftExpr(self.state.solver.constExpr(1, dst[1]), srcval) #2^srcval
        res = self.state.solver.andExpr(dstval, mask)
        result = self.state.solver.getBoolFromBitvector(res)
        self.updateFlags('BT', result)
        
        clearmask = self.state.solver.notExpr(mask)
        newdstval = self.state.solver.andExpr(dstval, clearmask)
        self.setValueFromState(dst, newdstval)
        
    def analyzeBTS(self, op):
        """The destination bit indexed by the source value is copied into the Carry Flag and then set."""
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        dstval = self.getValueFromState(dst)
        srcval = self.getValueFromState(src)
        srcval = self.fixOP2(srcval, dst[1])
        
        mask = self.state.solver.leftShiftExpr(self.state.solver.constExpr(1, dst[1]), srcval) #2^srcval
        res = self.state.solver.andExpr(dstval, mask)
        result = self.state.solver.getBoolFromBitvector(res)
        self.updateFlags('BT', result)
        
        newdstval = self.state.solver.orExpr(dstval, mask)
        self.setValueFromState(dst, newdstval)
        
    def analyzeCMP(self, op):
        """ like SUB but just updating the flags """
        dst = self.buildState(op, 0); dstval = self.getValueFromState(dst)
        src = self.buildState(op, 1); srcval = self.getValueFromState(src); srcval = self.fixOP2(srcval, dst[1])
        res = self.state.solver.subExpr(dstval, srcval)
        self.updateFlags("SUB", res, dstval, srcval)
        
    def analyzeTEST(self, op):
        """ like AND but just updating the flags """
        dst = self.buildState(op, 0); dstval = self.getValueFromState(dst)
        src = self.buildState(op, 1); srcval = self.getValueFromState(src); srcval = self.fixOP2(srcval, dst[1])
        res = self.state.solver.andExpr(dstval, srcval)
        self.updateFlags("LOGIC", res, dstval, srcval)
    
    def analyzeCLC(self, op):
        self.state.flags["_CF"] = self.state.solver.false
        
    def analyzeCLD(self, op):
        self.state.flags["_DF"] = self.state.solver.false
    
    def analyzeCMC(self, op):
        self.state.flags["_CF"] = self.state.solver.boolNotExpr(self.state.flags["_CF"])

    def analyzeSTC(self, op):
        self.state.flags["_CF"] = self.state.solver.true
        
    def analyzeSTD(self, op):
        self.state.flags["_DF"] = self.state.solver.true
        
    def analyzeCWDE(self, op):
        """extend sign bit of AX through EAX"""
        
        self.state.regs['EAX'] = self.state.solver.signExtendExpr(self.state.solver.extractExpr(self.state.regs['EAX'], 0, 15), 32)
    
    def analyzeCBW(self, op):
        """extend sign bit of AL through AX"""
        
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], \
                                                  self.state.solver.signExtendExpr(self.state.solver.extractExpr(self.state.regs['EAX'], 0, 7), 16), 16)
    
    def analyzeCWD(self, op):
        """extend sign bit of AX through DX"""
        self.state.regs['EDX'] = self.state.solver.assignExpr(self.state.regs['EDX'], \
                                                  self.state.solver.extractExpr(self.state.solver.signExtendExpr(self.state.solver.extractExpr(\
                                                      self.state.regs['EAX'], 0, 15), 32), 16, 31), 16)
            
    def analyzeCDQ(self, op):
        """extend sign bit of EAX through EDX"""
        self.state.regs['EDX'] = self.state.solver.extractExpr(self.state.solver.signExtendExpr(self.state.regs['EAX'], 64), 32, 63)
            
    def analyzeCMPS(self, op):
        self.analyzeCMP(op)
        self.state.regs["ESI"]=self.state.solver.iteExpr(self.state.flags["_DF"], 
        self.state.solver.subExpr(self.state.regs["ESI"], self.state.solver.constExpr(op.op1Size(), 32)),
        self.state.solver.addExpr(self.state.regs["ESI"], self.state.solver.constExpr(op.op1Size(), 32)))
        self.state.regs["EDI"]=self.state.solver.iteExpr(self.state.flags["_DF"], 
        self.state.solver.subExpr(self.state.regs["EDI"], self.state.solver.constExpr(op.op1Size(), 32)),
        self.state.solver.addExpr(self.state.regs["EDI"], self.state.solver.constExpr(op.op1Size(), 32)))
    
    def analyzeSCAS(self, op):
        self.analyzeCMP(op)
        self.state.regs["EDI"]=self.state.solver.iteExpr(self.state.flags["_DF"], 
        self.state.solver.subExpr(self.state.regs["EDI"], self.state.solver.constExpr(op.op1Size(), 32)),
        self.state.solver.addExpr(self.state.regs["EDI"], self.state.solver.constExpr(op.op1Size(), 32)))
        
    def analyzeSTOS(self, op):
        dst = self.buildState(op, 0)
        src = self.buildState(op, 1)
        srcvalue = self.getValueFromState(src)
        self.setValueFromState(dst, srcvalue)
        self.state.regs["EDI"]=self.state.solver.iteExpr(self.state.flags["_DF"], 
        self.state.solver.subExpr(self.state.regs["EDI"], self.state.solver.constExpr(op.op1Size(), 32)),
        self.state.solver.addExpr(self.state.regs["EDI"], self.state.solver.constExpr(op.op1Size(), 32)))
    
    def analyzeLODS(self, op):
        src = self.buildState(op, 0)
        srcvalue = self.getValueFromState(src)
        self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], srcvalue, src[1])
        self.state.regs["ESI"]=self.state.solver.iteExpr(self.state.flags["_DF"], 
        self.state.solver.subExpr(self.state.regs["ESI"], self.state.solver.constExpr(op.op1Size(), 32)),
        self.state.solver.addExpr(self.state.regs["ESI"], self.state.solver.constExpr(op.op1Size(), 32)))
    
    def analyzeCMPXCHG(self, op):
        """Logic:
        (* accumulator  AL, AX, or EAX, depending on whether *)
        (* a byte, word, or doubleword comparison is being performed*)
        IF accumulator == DEST
        THEN
        ZF = 1
        DEST = SRC
        ELSE
        ZF = 0
        accumulator = DEST
        FI;
        """
        dst = self.buildState(op, 0)
        dstval = self.getValueFromState(dst)
        src = self.buildState(op, 1)
        srcval = self.getValueFromState(src)
        
        bitsize = dst[1]
        accumulator = self.state.solver.extractExpr(self.state.regs['EAX'], 0, bitsize-1)
        
        ifpart = self.state.solver.eqExpr(accumulator, dstval)
        finaldest = self.state.solver.iteExpr(ifpart, srcval, dstval)
        finalaccum = self.state.solver.iteExpr(ifpart, accumulator, dstval)
        self.setValueFromState(dst, finaldest)
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], finalaccum, bits=bitsize)
        
        self.updateFlags('CMPXCHG', ifpart)
        
    def analyzeCMPXCHG8B(self, op):
        """Logic:
        IF (EDX:EAX == DEST)
        ZF = 1
        DEST = ECX:EBX
        ELSE
        ZF = 0
        EDX:EAX = DEST
        """
        dst = self.buildState(op, 0)
        dstval = self.getValueFromState(dst) #it has 64bits
        
        edxeax = self.state.solver.concatExpr(self.state.regs['EDX'], self.state.regs['EAX'])
        ecxebx = self.state.solver.concatExpr(self.state.regs['ECX'], self.state.regs['EBX'])
        ifpart = self.state.solver.eqExpr(edxeax, dstval)
        finaldst = self.state.solver.iteExpr(ifpart, ecxebx, dstval)
        finaledxeax = self.state.solver.iteExpr(ifpart, edxeax, dstval)
        
        self.setValueFromState(dst, finaldst)
        self.state.regs['EDX'] = self.state.solver.extractExpr(finaledxeax, 32, 63)
        self.state.regs['EAX'] = self.state.solver.extractExpr(finaledxeax, 0, 31)
        
        self.updateFlags('CMPXCHG', ifpart)

    def analyzeDAA(self, op):
        """Logic:
        origAL = AL
        origCF = CF
        IF (((AL AND 0FH) > 9) or AF == 1)
        THEN
        AL = AL + 6;
        CF = origCF OR CarryFromLastAddition; (* CF OR carry from AL = AL + 6 *)
        AF = 1;
        ELSE
        AF = 0;
        FI;
        IF ((origAL AND F0H) > 90H) or origCF == 1)
        THEN
        AL = AL + 60H;
        CF = 1;
        ELSE
        CF = 0;
        FI;
        """
        exprAL = self.state.solver.extractExpr(self.state.regs['EAX'], 0, 7)
        expr1 = self.state.solver.andExpr(exprAL, self.state.solver.constExpr(0xf, bits=8))
        expr2 = self.state.solver.gtExpr(expr1, self.state.solver.constExpr(9, bits=8))
        
        ifpart = self.state.solver.boolOrExpr(expr2, self.state.flags['_AF'])
        thenpart = self.state.solver.addExpr(exprAL, self.state.solver.constExpr(6, bits=8))
        elsepart = exprAL
        newAL = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        
        expr1 = self.state.solver.andExpr(exprAL, self.state.solver.constExpr(0xf0, bits=8))
        expr2 = self.state.solver.gtExpr(expr1, self.state.solver.constExpr(0x90, bits=8))
        
        ifpart2 = self.state.solver.boolOrExpr(expr2, self.state.flags['_CF'])
        thenpart = self.state.solver.addExpr(newAL, self.state.solver.constExpr(0x60, bits=8))
        elsepart = newAL        
        finalAL = self.state.solver.iteExpr(ifpart2, thenpart, elsepart)
        
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], finalAL, bits=8)
        
        #CF = 1 IF:
        #(((AL AND 0FH) > 9) or AF == 1)  AND (origCF OR CarryFromLastAddition; (* CF OR carry from AL = AL + 6 *))
        #OR
        #(origAL AND F0H) > 90H) or origCF == 1)
        #args: ifpart1, origAL, ifpart2
        tmp1=self.state.solver.boolAndExpr(ifpart, self.state.solver.boolOrExpr(self.state.flags['_CF'], self.state.solver.gtExpr(exprAL, self.state.solver.constExpr(0xf9, bits=8))))
        self.state.flags["_CF"]=self.state.solver.boolOrExpr(tmp1, ifpart2)
        self.state.flags['_AF']=ifpart
        self.updateFlags("DAA", finalAL, exprAL)
        
    def analyzeDAS(self, op):
        """Logic:
        origAL = AL
        origCF = CF
        IF (AL AND 0FH) > 9 OR AF == 1
        THEN
        AL = AL - 6;
        CF = origCF OR BorrowFromLastSubtraction; (* CF OR borrow from AL AL - 6 *)
        AF = 1;
        ELSE AF = 0;
        FI;
        IF ((origAL > 9FH) or origCF == 1)
        THEN
        AL = AL - 60H;
        CF = 1;
        ELSE CF = 0;
        FI;
        """
        exprAL = self.state.solver.extractExpr(self.state.regs['EAX'], 0, 7)
        expr1 = self.state.solver.andExpr(exprAL, self.state.solver.constExpr(0xf, bits=8))
        expr2 = self.state.solver.gtExpr(expr1, self.state.solver.constExpr(9, bits=8))
        
        ifpart = self.state.solver.boolOrExpr(expr2, self.state.flags['_AF'])
        thenpart = self.state.solver.subExpr(exprAL, self.state.solver.constExpr(6, bits=8))
        elsepart = exprAL
        newAL = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        
        expr1 = self.state.solver.gtExpr(exprAL, self.state.solver.constExpr(0x9f, bits=8))
        ifpart2 = self.state.solver.boolOrExpr(expr1, self.state.flags['_CF'])
        thenpart = self.state.solver.subExpr(newAL, self.state.solver.constExpr(0x60, bits=8))
        elsepart = newAL
        finalAL = self.state.solver.iteExpr(ifpart2, thenpart, elsepart)
        
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], finalAL, bits=8)
        
        #CF = 1 IF:
        #(((AL AND 0FH) > 9) or AF == 1)  AND (origCF OR BorrowFromLastSubtraction; (* CF OR borrow from AL AL - 6 *))
        #OR
        #(origAL > 9FH) or origCF == 1)
        #args: ifpart, origAL, ifpart2
        tmp1=self.state.solver.boolAndExpr(ifpart, self.state.solver.boolOrExpr(self.state.flags['_CF'], self.state.solver.ltExpr(exprAL, self.state.solver.constExpr(0x6, bits=8))))
        self.state.flags["_CF"]=self.state.solver.boolOrExpr(tmp1, ifpart2)
        self.state.flags['_AF']=ifpart
        self.updateFlags("DAS", finalAL, exprAL)
    
    def analyzeMUL(self, op):
        op1 = self.buildState(op, 0)
        op1val = self.getValueFromState(op1)
        
        if op1[1] == 8:
            acc = self.state.solver.extractExpr(self.state.regs["EAX"], 0, 7)
            res = self.state.solver.umulExpr(acc, op1val, 16)
            self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], res, 16)
        elif op1[1] == 16:
            acc = self.state.solver.extractExpr(self.state.regs["EAX"], 0, 15)
            res = self.state.solver.umulExpr(acc, op1val, 32)
            self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], self.state.solver.extractExpr(res, 0, 15), 16)
            self.state.regs["EDX"] = self.state.solver.assignExpr(self.state.regs["EDX"], self.state.solver.extractExpr(res, 16, 31), 16)
        else:
            #32bits
            acc = self.state.regs["EAX"]
            res = self.state.solver.umulExpr(acc, op1val, 64)
            self.state.regs["EAX"] = self.state.solver.extractExpr(res, 0, 31)
            self.state.regs["EDX"] = self.state.solver.extractExpr(res, 32, 63)
        self.updateFlags("MUL", res, acc, op1val)
        
    def analyzeIMUL(self, op):
        """
        May be one of the worst specified instructions ever...
        If there is just 1 operand, act as MUL but signed.
        If there are 2 operands multiply both and store result in op1 (if op2 is an imm8 it's signextended to op1size)
        If there are 3 operands, multiply op2 with op3 (if op3 is an imm8 sigextend it to op1size) and then multiply by op1
        """
        op1 = self.buildState(op, 0)
        op1val = self.getValueFromState(op1)
        opcount=1
        if op.op2Type():
            opcount=2
            op2 = self.buildState(op, 1)
            op2val = self.fixOP2(self.getValueFromState(op2), op1[1])
        if op.op3Type():
            opcount=3
            op3 = self.buildState(op, 2)
            op3val = self.fixOP2(self.getValueFromState(op3), op1[1])
        
        if opcount == 1:
            if op1[1] == 8:
                acc = self.state.solver.extractExpr(self.state.regs["EAX"], 0, 7)
                res = self.state.solver.smulExpr(acc, op1val, 16)
                self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], res, 16)
            elif op1[1] == 16:
                acc = self.state.solver.extractExpr(self.state.regs["EAX"], 0, 15)
                res = self.state.solver.smulExpr(acc, op1val, 32)
                self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], self.state.solver.extractExpr(res, 0, 15), 16)
                self.state.regs["EDX"] = self.state.solver.assignExpr(self.state.regs["EDX"], self.state.solver.extractExpr(res, 16, 31), 16)
            else:
                #32bits
                acc = self.state.regs["EAX"]
                res = self.state.solver.smulExpr(acc, op1val, 64)
                self.state.regs["EAX"] = self.state.solver.extractExpr(res, 0, 31)
                self.state.regs["EDX"] = self.state.solver.extractExpr(res, 32, 63)
            self.updateFlags("IMUL", res, acc, op1val)
        else:
            if opcount == 3:
                tmp = self.state.solver.smulExpr(op2val, op3val, op1[1]*2)
            else:
                tmp = op2val
            res = self.state.solver.smulExpr(op1val, tmp, op1[1]*2)
            self.setValueFromState(op1, self.state.solver.extractExpr(res, 0, op1[1]-1))
            self.updateFlags("IMUL", res, op1val, tmp)
    
    def analyzeDIV(self, op):
        """
        IF SRC == 0:
            #DE
        FI
        IF opsize == 8:
            IF acc / SRC > 0FFh:
                #DE
            FI
            AH = acc MOD SRC
            AL = acc / SRC
        FI
        (same with 16 using DX:AX and with 32 using EDX:EAX)
        """
        op1 = self.buildState(op, 0)
        op1val = self.getValueFromState(op1)
        maxval = self.state.solver.constExpr((2 ** op1[1]) - 1, op1[1]*2)
        
        if op1[1] == 8:
            div = self.state.solver.extractExpr(self.state.regs["EAX"], 0, 15)
            res = self.state.solver.udivExpr(div, op1val)
            mod = self.state.solver.uremExpr(div, op1val)
            self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], mod, 8, 8) #AH
            self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], res, 8, 0) #AL
        elif op1[1] == 16:
            div = self.state.solver.concatExpr(self.state.solver.extractExpr(self.state.regs["EDX"], 0, 15), \
                                         self.state.solver.extractExpr(self.state.regs["EAX"], 0, 15))
            res = self.state.solver.udivExpr(div, op1val)
            mod = self.state.solver.uremExpr(div, op1val)
            self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], self.state.solver.extractExpr(res, 0, 15), 16)
            self.state.regs["EDX"] = self.state.solver.assignExpr(self.state.regs["EDX"], self.state.solver.extractExpr(mod, 0, 15), 16)
        else:
            #32bits
            div = self.state.solver.concatExpr(self.state.regs["EDX"], self.state.regs["EAX"]) #this is 64bits
            res = self.state.solver.udivExpr(div, op1val)
            mod = self.state.solver.uremExpr(div, op1val)
            self.state.regs["EAX"] = self.state.solver.extractExpr(res, 0, 31)
            self.state.regs["EDX"] = self.state.solver.extractExpr(mod, 0, 31)
        
        #IF SRC == 0 OR acc / SRC > maxval
        self.state.exceptions["#DE"] = self.state.solver.boolOrExpr(self.state.solver.eqExpr(op1val, self.state.solver.constExpr(0, op1[1])), \
                                                         self.state.solver.gtExpr(res, maxval))
    
    def analyzeIDIV(self, op):
        """
        IF SRC == 0:
            #DE
        FI
        IF opsize == 8:
            IF acc / SRC > 07Fh OR acc / SRC < 80h:
                (* If a positive result is greater than 7FH or a negative result is less than 80H *)
                #DE
            FI
            AH = acc SMOD SRC
            AL = acc / SRC
        FI
        (same with 16 using DX:AX and with 32 using EDX:EAX)
        """
        op1 = self.buildState(op, 0)
        op1val = self.getValueFromState(op1)
        maskval = self.state.solver.constExpr((2 ** op1[1]-1), op1[1]*2)
        
        if op1[1] == 8:
            div = self.state.solver.extractExpr(self.state.regs["EAX"], 0, 15)
            res = self.state.solver.sdivExpr(div, op1val)
            mod = self.state.solver.sremExpr(div, op1val)
            self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], mod, 8, 8) #AH
            self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], res, 8, 0) #AL
        elif op1[1] == 16:
            div = self.state.solver.concatExpr(self.state.solver.extractExpr(self.state.regs["EDX"], 0, 15), \
                                         self.state.solver.extractExpr(self.state.regs["EAX"], 0, 15))
            res = self.state.solver.sdivExpr(div, op1val)
            mod = self.state.solver.sremExpr(div, op1val)
            self.state.regs["EAX"] = self.state.solver.assignExpr(self.state.regs["EAX"], self.state.solver.extractExpr(res, 0, 15), 16)
            self.state.regs["EDX"] = self.state.solver.assignExpr(self.state.regs["EDX"], self.state.solver.extractExpr(mod, 0, 15), 16)
        else:
            #32bits
            div = self.state.solver.concatExpr(self.state.regs["EDX"], self.state.regs["EAX"]) #this is 64bits
            res = self.state.solver.sdivExpr(div, op1val)
            mod = self.state.solver.sremExpr(div, op1val)
            self.state.regs["EAX"] = self.state.solver.extractExpr(res, 0, 31)
            self.state.regs["EDX"] = self.state.solver.extractExpr(mod, 0, 31)
        
        #IF SRC == 0 OR acc == maskval OR res != SX(res & maxval)
        self.state.exceptions["#DE"] = self.state.solver.boolOrExpr(self.state.solver.eqExpr(op1val, self.state.solver.constExpr(0, op1[1])), \
                                 self.state.solver.boolOrExpr(self.state.solver.eqExpr(div, maskval), \
                                                        self.state.solver.neExpr(res, self.state.solver.signExtendExpr(self.state.solver.extractExpr(res, 0, op1[1]-1), op1[1]*2))))
    
    def analyzeSETO(self, op):
        #90
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.flags["_OF"], 8)
        self.setValueFromState(dst, value)
        
    def analyzeSETNO(self, op):
        #91
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.boolNotExpr(self.state.flags["_OF"]), 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETB(self, op):
        #92
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.flags["_CF"], 8)
        self.setValueFromState(dst, value)
        
    def analyzeSETNB(self, op):
        #93
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.boolNotExpr(self.state.flags["_CF"]), 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETE(self, op):
        #94
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.flags["_ZF"], 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETNE(self, op):
        #95
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.boolNotExpr(self.state.flags["_ZF"]), 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETBE(self, op):
        #96
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.boolOrExpr(self.state.flags["_CF"], self.state.flags["_ZF"]) , 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETA(self, op):
        #97
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.boolAndExpr(self.state.solver.boolNotExpr(self.state.flags["_CF"]), self.state.solver.boolNotExpr(self.state.flags["_ZF"])) , 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETS(self, op):
        #98
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.flags["_SF"], 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETNS(self, op):
        #99
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.boolNotExpr(self.state.flags["_SF"]), 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETPE(self, op):
        #9A
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.flags["_PF"], 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETPO(self, op):
        #9B
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.boolNotExpr(self.state.flags["_PF"]), 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETL(self, op):
        #9C
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.iffExpr(self.state.flags["_SF"], self.state.solver.boolNotExpr(self.state.flags["_OF"])), 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETGE(self, op):
        #9D
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.iffExpr(self.state.flags["_SF"], self.state.flags["_OF"]), 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETLE(self, op):
        #9E
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.boolOrExpr(self.state.flags["_ZF"], self.state.solver.iffExpr(self.state.flags["_SF"], self.state.solver.boolNotExpr(self.state.flags["_OF"]))), 8)
        self.setValueFromState(dst, value)
    
    def analyzeSETG(self, op):
        #9F
        dst = self.buildState(op, 0)
        value=self.state.solver.getBitvectorFromBool(self.state.solver.boolAndExpr(self.state.solver.boolNotExpr(self.state.flags["_ZF"]), self.state.solver.iffExpr(self.state.flags["_SF"], self.state.flags["_OF"])), 8)
        self.setValueFromState(dst, value)
        
    def analyzeXADD(self, op):
        """Logic:
        newDST = SRC + DEST
        newSRC = DEST
        """
        dst = self.buildState(op, 0)
        dstval = self.getValueFromState(dst)
        src = self.buildState(op, 1)
        srcval = self.getValueFromState(src)
        srcval = self.fixOP2(srcval, dst[1])
        
        self.setValueFromState(dst, self.state.solver.addExpr(srcval, dstval))
        self.setValueFromState(src, dstval)
        
    def analyzeXLAT(self, op):
        """AL = *(DS:EBX + ZeroExtend(AL))"""
        zeroExtendedAL = self.state.solver.zeroExtendExpr(self.state.solver.extractExpr(self.state.regs['EAX'], 0, 7), 32)
        readAddr = self.state.solver.addExpr(self.state.regs['EBX'], zeroExtendedAL)
        value = self.getMemoryStateFromSolverState(readAddr, 8) #if we have the address to read already solved, just go for it
        self.state.regs['EAX'] = self.state.solver.assignExpr(self.state.regs['EAX'], value, bits=8)
    
    def analyzeJMP(self, op):
        """
        Possibilities: JMP reg, JMP mem, JMP rel.
        (Far Jumps are not supported)
        """
        if op.op1Type() == 0:
            #this is a rel16/rel32 jump
            neweip = op.jmpaddr - self.initialAddress
            self.state.EIP = self.state.solver.addExpr(
                self.state.solver.lookupVar("EIP")[0],
                self.state.solver.constExpr(neweip))
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
    
    def analyzeCALL(self, op):
        self.state.isCall = True
        #EIP is already pointing to the next instruction
        self.state.regs['ESP'] = self.state.solver.subExpr(self.state.regs['ESP'], self.state.solver.constExpr(4))
        self.setMemoryStateFromSolverState(self.state.regs["ESP"], self.state.EIP, 32)

        self.analyzeJMP(op)
    
    def analyzeJcc(self, condition, finaladdress):
        """
        Jcc opcodes: 70-7F, E3, 0F 80-8F
        All Jcc opcodes end up here, <condition> is a BOOLEAN expr that must be TRUE to jump and <finaladdress> is the final offset to jump to.
        
        This is an special case as we analyze the rest of the sequence from here, iterating over self.analyze and puting ITE in all the changed states.
        Beaware of loops!, as the current implementation would try to unwind them endlessly.
        """
        
        if self._debug: self.imm.log("CONDITIONAL BRANCHING, cond=%s"%self.state.solver.exprString(condition))
        
        notused8bits = self.state.solver.varExpr("NOTUSED8", self.state.solver.bv8bits)
        notused32bits = self.state.solver.varExpr("NOTUSED32", self.state.solver.bv32bits)
        notusedbool = self.state.solver.varExpr("NOTUSEDBOOL", self.state.solver.booltype)

        self.state.solver.push()
        #check if this branch is satisfiable
        ret=self.state.solver.checkUnsat(condition)
        self.state.solver.pop()

        if not ret:
            if self._debug: self.imm.log("############################ True Branch ##########################################", finaladdress)
            
            #analyze the true condition
            self.push()
            
            #assert the condition as true and set everything for analysis
            self.state.solver.assertFormula(condition)
            
            #calculate the jump address
            eip = self.state.solver.lookupVar("EIP")[0]
            relativeAddress = (finaladdress - self.initialAddress) & 0xffffffff
            self.state.EIP=self.state.solver.addExpr(eip, self.state.solver.constExpr(relativeAddress))
            
            if not self.analyze():
                errors = copy(self.errors)
                self.pop()
                self.errors += errors
                #An error was found while analysing the True branch
                self.reportError(ConditionalBranchException, True)
            self.push()
            trueState=self.pop()
            
            self.pop()
        else:
            trueState=self.makeClean(notused32bits, notusedbool)
        
        self.state.solver.push()
        #check if this branch is satisfiable
        ret=self.state.solver.checkUnsat(self.state.solver.boolNotExpr(condition))
        self.state.solver.pop()
        
        self.jcc_not_taken = not ret

        if not ret:
            if self._debug: self.imm.log("############################ False Branch ##########################################", self.lastAddress)
            
            #analyze the false condition
            self.push()
            
            #assert the condition as false
            self.state.solver.assertFormula(self.state.solver.boolNotExpr(condition))
            
            if not self.analyze():
                errors = copy(self.errors)
                self.pop()
                self.errors += errors
                #An error was found while analysing the False branch
                self.reportError(ConditionalBranchException, False)
            self.push()
            falseState=self.pop()
            
            self.pop()
        else:
            falseState=self.makeClean(notused32bits, notusedbool)
        
        #(regs, flags, exceptions, memsources, undefvalues, mem, eip)
        for key in self.state.regs.keys():
            if self.compareWithCondition(condition, trueState[0][key], falseState[0][key]):
                self.state.regs[key] = falseState[0][key]
            else: 
                self.state.regs[key] = self.state.solver.iteExpr(condition, trueState[0][key], falseState[0][key])
        
        for key in self.state.flags.keys():
            if self.compareWithCondition(condition, trueState[1][key], falseState[1][key]):
                self.state.flags[key] = falseState[1][key]
            else:
                self.state.flags[key] = self.state.solver.iteExpr(condition, trueState[1][key], falseState[1][key])
        
        for key in self.state.exceptions.keys():
            if self.compareWithCondition(condition, trueState[2][key], falseState[2][key]):
                self.state.exceptions[key] = falseState[2][key]
            else:
                self.state.exceptions[key] = self.state.solver.iteExpr(condition, trueState[2][key], falseState[2][key])
        
        for k,v in trueState[3].iteritems():
            self.state.memory.sources[k]=v
        for k,v in falseState[3].iteritems():
            self.state.memory.sources[k]=v
        
        for k,v in trueState[4].iteritems():
            self.state.memory.undefvalues[k]=v
        for k,v in falseState[4].iteritems():
            self.state.memory.undefvalues[k]=v
        
        #unique list of mem keys
        keys = list(set(trueState[5].keys() + falseState[5].keys()))
        for key in keys:
            trueoption = falseoption = None
            if trueState[5].has_key(key):
                trueoption = trueState[5][key]
            if falseState[5].has_key(key):
                falseoption = falseState[5][key]
            
            if trueoption and falseoption:
                if self.compareWithCondition(condition, trueoption, falseoption):
                    self.state.memory[key] = falseoption
                else:
                    self.state.memory[key] = self.state.solver.iteExpr(condition, trueoption, falseoption)
            elif trueoption:
                self.state.memory[key] = trueoption
            elif falseoption:
                self.state.memory[key] = falseoption
        
        if self.compareWithCondition(condition, trueState[6], falseState[6]):
            self.state.EIP = falseState[6]
        else:
            self.state.EIP = self.state.solver.iteExpr(condition, trueState[6], falseState[6])
        
        #tell self.analyze that we processed the entire sequence
        raise ConditionalJumpException
    
    def compareWithCondition(self, condition, trueval, falseval):
        """
        Here we try to handle this case:
        IF var=X THEN X ELSE X, which should be simplified as X
        """
        
        self.state.solver.push()
        self.state.solver.assertFormula(condition)
        ret=self.state.solver.compareExpr(trueval, falseval)
        self.state.solver.pop()
        return ret
    
    def analyzeJO(self, op):
        #70
        cond=self.state.flags["_OF"]
        self.analyzeJcc(cond, op.jmpaddr)
        
    def analyzeJNO(self, op):
        #71
        cond=self.state.solver.boolNotExpr(self.state.flags["_OF"])
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJB(self, op):
        #72
        cond=self.state.flags["_CF"]
        self.analyzeJcc(cond, op.jmpaddr)
        
    def analyzeJNB(self, op):
        #73
        cond=self.state.solver.boolNotExpr(self.state.flags["_CF"])
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJE(self, op):
        #74
        cond=self.state.flags["_ZF"]
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJNZ(self, op):
        #75
        cond=self.state.solver.boolNotExpr(self.state.flags["_ZF"])
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJBE(self, op):
        #76
        cond=self.state.solver.boolOrExpr(self.state.flags["_CF"], self.state.flags["_ZF"])
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJA(self, op):
        #77
        cond=self.state.solver.boolAndExpr(self.state.solver.boolNotExpr(self.state.flags["_CF"]), self.state.solver.boolNotExpr(self.state.flags["_ZF"]))
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJS(self, op):
        #78
        cond=self.state.flags["_SF"]
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJNS(self, op):
        #79
        cond=self.state.solver.boolNotExpr(self.state.flags["_SF"])
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJPE(self, op):
        #7A
        cond=self.state.flags["_PF"]
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJPO(self, op):
        #7B
        cond=self.state.solver.boolNotExpr(self.state.flags["_PF"])
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJL(self, op):
        #7C
        cond=self.state.solver.iffExpr(self.state.flags["_SF"], self.state.solver.boolNotExpr(self.state.flags["_OF"]))
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJGE(self, op):
        #7D
        cond=self.state.solver.iffExpr(self.state.flags["_SF"], self.state.flags["_OF"])
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJLE(self, op):
        #7E
        cond=self.state.solver.boolOrExpr(self.state.flags["_ZF"], self.state.solver.iffExpr(self.state.flags["_SF"], self.state.solver.boolNotExpr(self.state.flags["_OF"])))
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJG(self, op):
        #7F
        cond=self.state.solver.boolAndExpr(self.state.solver.boolNotExpr(self.state.flags["_ZF"]), self.state.solver.iffExpr(self.state.flags["_SF"], self.state.flags["_OF"]))
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJCXZ(self, op):
        #67:E3
        cond=self.state.solver.eqExpr(self.state.solver.extractExpr(self.state.regs["ECX"], 0, 15), self.state.solver.constExpr(0, 16))
        self.analyzeJcc(cond, op.jmpaddr)
    
    def analyzeJECXZ(self, op):
        #E3
        cond=self.state.solver.eqExpr(self.state.regs["ECX"], self.state.solver.constExpr(0, 32))
        self.analyzeJcc(cond, op.jmpaddr)
        
    ################### Analyze helpers #######################
    
    def solveArithmetic(self, cmd, dst, src=None):
        """
        All generic arithmetic functions share the same working principle
        cmd is a function pointer to a Solver function to execute
        
        It returns a 3-tuple with: the result of the operation, the original dst value, and the original src value.
        """
        
        if src != None:
            srcvalue = self.getValueFromState(src)
            srcvalue = self.fixOP2(srcvalue, dst[1])
        else:
            srcvalue = None
        
        dstvalue = self.getValueFromState(dst)
        if src != None:
            res = cmd(dstvalue, srcvalue)
        else:
            res = cmd(dstvalue)
        
        self.setValueFromState(dst, res)
        
        return (res, dstvalue, srcvalue)
    
    def updateFlags(self, cmd, res, op1=None, op2=None, op3=None):
        self.state.flags.updateargs = (cmd, res, op1, op2, op3)
        self.state.flags.needsupdate=True
    
    def updateFlagsReal(self, cmd, res, op1=None, op2=None, op3=None):
        """
        OP2 must have the ID bug fixed (like done in solveArithmetic)
        LOGIC=AND,OR,XOR,TEST
        some code used for the flag updating was taken from bochs
        """
        
        if op1 != None:
            op1size=self.state.solver.getBitSizeFromExpr(op1)
            mask = (2 ** op1size) - 1
            sign_mask = self.state.solver.constExpr((mask + 1) / 2, op1size)
            mask = self.state.solver.constExpr(mask, op1size)
        
        if op2 != None: op2size = self.state.solver.getBitSizeFromExpr(op2)
        if op3 != None: op3size = self.state.solver.getBitSizeFromExpr(op3)
        
        #Carry Flag
        elif cmd == "ADD":
            self.state.flags["_CF"] = self.state.solver.ltExpr(res, op1)
        elif cmd == "ADC":
            #Logic from bochs: an ADC with CF=false is an ADD
            ifpart = self.state.flags['_CF']
            thenpart = self.state.solver.leExpr(res, op1)
            elsepart = self.state.solver.ltExpr(res, op1)
            self.state.flags["_CF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd == 'SUB':
            self.state.flags["_CF"] = self.state.solver.ltExpr(op1, op2)
        elif cmd == "SBB":
            ifpart = self.state.flags["_CF"]
            thenpart = self.state.solver.boolOrExpr(self.state.solver.ltExpr(op1, res), self.state.solver.eqExpr(op2, mask))
            elsepart = self.state.solver.ltExpr(op1, op2) #like a normal SUB
            self.state.flags["_CF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd == "NEG":
            self.state.flags["_CF"] = self.state.solver.neExpr(res, self.state.solver.constExpr(0, op1size))
        elif cmd == "LOGIC":
            self.state.flags["_CF"] = self.state.solver.false
        elif cmd in ["SHR", "SHRD", "SAR"]:
            smallzero = self.state.solver.constExpr(0, 1)
            tmp = self.state.solver.boolExtractExpr(self.state.solver.rightShiftExpr(
                  self.state.solver.concatExpr(op1, smallzero), op2, op1size + 1), 0)
            
            #if counter is 0 nothing should be changed
            ifpart = self.state.solver.gtExpr(op2, self.state.solver.constExpr(0, op1size))
            thenpart = tmp
            elsepart = self.state.flags["_CF"]
            self.state.flags["_CF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd in ["SHL", "SHLD"]:
            smallzero = self.state.solver.constExpr(0, 1)
            tmp = self.state.solver.boolExtractExpr(self.state.solver.leftShiftExpr(
                  self.state.solver.concatExpr(smallzero, op1), op2, op1size + 1), op1size)
            
            #if counter is 0 nothing should be changed
            ifpart = self.state.solver.gtExpr(op2, self.state.solver.constExpr(0, op1size))
            thenpart = tmp
            elsepart = self.state.flags["_CF"]
            self.state.flags["_CF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd == "MUL":
            #res is 2*op1size bits
            #CF is set if the upper half of the result != 0
            tmp = self.state.solver.extractExpr(res, op1size, (op1size*2)-1)
            self.state.flags["_CF"] = self.state.solver.getBoolFromBitvector(tmp)
        elif cmd == "IMUL":
            #res is 2*op1size bits
            #CF is set if res64 != signExtend(res32,64)
            lowerhalf = self.state.solver.extractExpr(res, 0, op1size-1)
            ifpart = self.state.solver.eqExpr(self.state.solver.signExtendExpr(lowerhalf, op1size*2), res)
            thenpart = self.state.solver.false
            elsepart = self.state.solver.true
            self.state.flags["_CF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd == "ROL":
            #if counter & 0x1f is 0 nothing should be changed
            ifpart = self.state.solver.gtExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(0, op2size))
            thenpart = self.state.solver.boolExtractExpr(res, 0)
            elsepart = self.state.flags["_CF"]
            self.state.flags["_CF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd == "ROR":
            #if counter & 0x1f is 0 nothing should be changed
            ifpart = self.state.solver.gtExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(0, op2size))
            thenpart = self.state.solver.boolExtractExpr(res, op1size-1)
            elsepart = self.state.flags["_CF"]
            self.state.flags["_CF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd in ["RCL", "RCR"]:
            #if counter & 0x1f is 0 nothing should be changed
            ifpart = self.state.solver.gtExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(0, op2size))
            thenpart = self.state.solver.boolExtractExpr(res, op1size) #33bit is the CF
            elsepart = self.state.flags["_CF"]
            self.state.flags["_CF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        
        #Overflow Flag
        #some OF depend on CF, so lets reuse that logic
        if cmd in [ "ADD", "ADC" ]:
            op1bit=self.state.solver.boolExtractExpr(op1, op1size-1)
            op2bit=self.state.solver.boolExtractExpr(op1, op1size-1)
            resbit=self.state.solver.boolExtractExpr(op1, op1size-1)
            xor1=self.state.solver.boolXorExpr(op1bit, resbit)
            xor2=self.state.solver.boolXorExpr(op2bit, resbit)
            self.state.flags["_OF"] = self.state.solver.boolAndExpr(xor1, xor2)
        elif cmd in [ "SUB", "SBB" ]:
            op1bit=self.state.solver.boolExtractExpr(op1, op1size-1)
            op2bit=self.state.solver.boolExtractExpr(op1, op1size-1)
            resbit=self.state.solver.boolExtractExpr(op1, op1size-1)
            xor1=self.state.solver.boolXorExpr(op1bit, op2bit)
            xor2=self.state.solver.boolXorExpr(op1bit, resbit)
            self.state.flags["_OF"] = self.state.solver.boolAndExpr(xor1, xor2)
        elif cmd in ["NEG"]:
            self.state.flags["_OF"] = self.state.solver.eqExpr(res, sign_mask)
        elif cmd in "LOGIC":
            self.state.flags["_OF"] = self.state.solver.false
        elif cmd in ["SHR"]:
            #is only set if counter & 0x1f == 1
            ifpart = self.state.solver.eqExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(1, op2size))
            thenpart = self.state.solver.geExpr(op1, sign_mask)
            elsepart = self.state.flags["_OF"]
            self.state.flags["_OF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd in ["SHRD"]:
            tmp1 = self.state.solver.boolExtractExpr(res, op1size-2)
            tmp2 = self.state.solver.boolExtractExpr(res, op1size-1)
            #of = res30 ^ res31
            
            #is only set if counter & 0x1f == 1
            ifpart = self.state.solver.eqExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(1, op2size))
            thenpart = self.state.solver.boolXorExpr(tmp1, tmp2)
            elsepart = self.state.flags["_OF"]
            self.state.flags["_OF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd == "SAR":
            #is only set if counter & 0x1f == 1
            ifpart = self.state.solver.eqExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(1, op2size))
            thenpart = self.state.solver.false
            elsepart = self.state.flags["_OF"]
            self.state.flags["_OF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd in ["SHL", "SHLD"]:
            tmp = self.state.solver.boolExtractExpr(res, op1size-1)
            #of = cf ^ res31
            
            #is only set if counter & 0x1f == 1
            ifpart = self.state.solver.eqExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(1, op2size))
            thenpart = self.state.solver.boolXorExpr(self.state.flags["_CF"], tmp)
            elsepart = self.state.flags["_OF"]
            self.state.flags["_OF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd in [ "IMUL", "MUL" ]:
            self.state.flags["_OF"] = self.state.flags["_CF"]
        elif cmd == "ROL":
            tmp1 = self.state.solver.boolExtractExpr(res, 0)
            tmp2 = self.state.solver.boolExtractExpr(res, op1size-1)
            #cf = res0
            #of = cf ^ res31
            
            #if counter & 0x1f is 0 nothing should be changed
            ifpart = self.state.solver.gtExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(0, op2size))
            thenpart = self.state.solver.boolXorExpr(tmp1, tmp2)
            elsepart = self.state.flags["_OF"]
            self.state.flags["_OF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd == "ROR":
            tmp1 = self.state.solver.boolExtractExpr(res, op1size-1)
            tmp2 = self.state.solver.boolExtractExpr(res, op1size-2)
            #of = res30 ^ res31
                
            #if counter & 0x1f is 0 nothing should be changed
            ifpart = self.state.solver.gtExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(0, op2size))
            thenpart = self.state.solver.boolXorExpr(tmp1, tmp2)
            elsepart = self.state.flags["_OF"]
            self.state.flags["_OF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd == "RCL":
            tmp = self.state.solver.boolXorExpr(
                self.state.solver.boolExtractExpr(res, op1size-1),
                self.state.solver.boolExtractExpr(res, op1size),
            ) #of = cf ^ res31
            
            #if counter & 0x1f is 0 nothing should be changed
            ifpart = self.state.solver.gtExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(0, op2size))
            thenpart = tmp
            elsepart = self.state.flags["_OF"]
            self.state.flags["_OF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        elif cmd == "RCR":
            tmp = self.state.solver.boolXorExpr(
                self.state.solver.boolExtractExpr(res, op1size-1),
                self.state.solver.boolExtractExpr(res, op1size-2),
            ) #of = res30 ^ res31
            
            #if counter & 0x1f is 0 nothing should be changed
            ifpart = self.state.solver.gtExpr(self.state.solver.andExpr(op2,self.state.solver.constExpr(0x1f, op2size)), self.state.solver.constExpr(0, op2size))
            thenpart = tmp
            elsepart = self.state.flags["_OF"]
            self.state.flags["_OF"] = self.state.solver.iteExpr(ifpart, thenpart, elsepart)
        
        #Adjust Flag
        elif cmd in ["ADD", "ADC", "SUB", "SBB"]:
            self.state.flags["_AF"] = self.state.solver.boolExtractExpr(self.state.solver.xorExpr(self.state.solver.xorExpr(op1, op2), res), 4)
        elif cmd == "NEG":
            self.state.flags["_AF"] = self.state.solver.neExpr(self.state.solver.extractExpr(res, 0, 3), self.state.solver.constExpr(0,4))
        elif cmd == "LOGIC":
            self.state.flags["_AF"] = self.state.solver.false
        
        #Sign Flag
        if cmd in ["LOGIC", "AAD", "AAM", "ADD", "ADC", "SUB", "SBB", "NEG", "SAR", "SHR", "SHL", "SHLD", "SHRD", "DAA", "DAS"]:
            self.state.flags["_SF"] = self.state.solver.boolExtractExpr(res, op1size-1)
        
        #Parity Flag
        if cmd in ["LOGIC", "AAD", "AAM", "ADD", "ADC", "SUB", "SBB", "NEG", "SHR", "SHL", "SHLD", "SHRD", "DAA", "DAS"]:
            tmp = self.state.solver.extractExpr(res, 0, op1size-1)
            count = op1size / 2
            while count >= 1:
                tmp = self.state.solver.xorExpr(tmp, self.state.solver.rightShiftExpr(tmp, count))
                count /= 2
            self.state.flags["_PF"] = self.state.solver.boolExtractExpr(self.state.solver.notExpr(tmp), 0)
            
        #Zero Flag
        if cmd in ["LOGIC", "AAD", "AAM", "ADD", "ADC", "BSF", "BSR", "SUB", "SBB", "NEG", "SAR", "SHR", "SHL", "SHLD", "SHRD", "DAA", "DAS"]:
            self.state.flags["_ZF"] = self.state.solver.eqExpr(res, self.state.solver.constExpr(0, op1size))
        elif cmd == "CMPXCHG":
            self.state.flags["_ZF"] = res #res is already a BOOLEAN
        
        if self.simplifyState:
            for key in self.state.flags.keys():
                self.state.flags[key] = self.state.solver.simplify(self.state.flags[key])
    
    #################### State handling #########################
    
    def getValueFromState(self, state):
        """
        returns a correctly formated value (to use in a resolver instance) and the correspondent position
        
        """
        
        if state[0][0] == 'mem':
            value = self.getMemoryState(state)
        elif state[0][0] == 'reg':
            if state[1] == 8:
                pos = 0
                if state[0][1] > 3: pos = 8 #reg positions > 3 are AH/BH/CH/DH
                value = self.state.solver.extractExpr(self.state.regs[Registers32BitsOrder[(state[0][1] % 4)]], pos, pos+7)
            elif state[1] == 16:
                value = self.state.solver.extractExpr(self.state.regs[Registers32BitsOrder[state[0][1]]], 0, 15)
            else:
                value = self.state.regs[Registers32BitsOrder[state[0][1]]]
        elif state[0][0] == 'con':
            value = self.state.solver.constExpr(state[0][1], state[1])
        elif state[0][0] == 'flag':
            value = self.state.solver.getBitvectorFromBool(self.state.flags[state[0][1]], state[1])
        else:
            reason = "we are in the oven... UNKNOWN state type"
            self.reportError(UnexpectedException, "Exception while analyzing '%s' at 0x%x: %s"%(self.lastDisasm, self.lastAddress, reason))
        
        return value

    def setValueFromState(self, state, value):
        if state[0][0] == 'mem':
            self.setMemoryState(state, value)
        elif state[0][0] == 'reg':
            pos = 0
            if state[1] == 8:
                dstreg = Registers32BitsOrder[(state[0][1] % 4)]
                if state[0][1] > 3: pos = 8 #reg positions > 3 are AH/BH/CH/DH
            else:
                dstreg = Registers32BitsOrder[state[0][1]]
            
            if state[1] != 32:
                self.state.regs[dstreg] = self.state.solver.assignExpr(self.state.regs[dstreg], value, state[1], pos)
            else:
                self.state.regs[dstreg] = value
        elif state[0][0] == 'flag':
            self.state.flags[state[0][1]] = self.state.solver.getBoolFromBitvector(value)
        else:
            reason = "Destination is not memory nor a register, what else can be?" #XXX: we don't support FPU/MMX/SSE/etc yet
            self.reportError(UnexpectedException, "Exception while analyzing '%s' at 0x%x: %s"%(self.lastDisasm, self.lastAddress, reason))
        
    def fixOP2(self, op2value, op1size):
        """
        This is a fix used many times in the code to fix a BUG in ID, where it sign-extends all constants to 32bits, even for 8-bits operations.
        If this is fixed someday, we'll remove all this.
        """
        
        if op2value != None and self.state.solver.getBitSizeFromExpr(op2value) > op1size:
            #const are declared as 32bits even when they're not and a src operand cannot be of diff size than the dst operand
            #This's because ID takes care of this (magically!), it sign-extends imm8/imm16 to 32bits when needed
            return self.state.solver.extractExpr(op2value, 0, op1size-1)
        return op2value

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
            self.reportError(UndefinedMemoryException, simplified)
        
        return addr

    def setMemoryState(self, stateandsize, value):
        """
        Set memory with a given value.
        
        Value is a resolver expression.
        """

        state = stateandsize[0]
        size = stateandsize[1]
        if state[0] != 'mem':
            reason = "trying to set a Memory space using a non-memory reference"
            self.reportError(UnexpectedException, "Exception while analyzing '%s' at 0x%x: %s"%(self.lastDisasm, self.lastAddress, reason))

        tmpstate = self.transformMemoryStateToSolverState(state)
        return self.setMemoryStateFromSolverState(tmpstate, value, size)
        
    def setMemoryStateFromSolverState(self, state, value, size):
        tmpstate=state
        if self.useCurrentMemory:
            tmp1 = "0x08%x"%self.getAddressFromState(state) #just for raising an exception if the address is not constant
        else:
            tmp1 = self.state.solver.UConstFromExpr(self.state.solver.simplify(state))
            if tmp1 == None: tmp1=self.state.solver.exprString(self.state.solver.simplify(state))
            else: tmp1 = "0x08%x"%tmp1
            
        if self._debug:
            tmp2 = self.state.solver.UConstFromExpr(self.state.solver.simplify(value))
            if tmp2 == None: tmp2=self.state.solver.exprString(self.state.solver.simplify(value))
            else: tmp2 = "0x%x"%tmp2
            
            self.imm.log("Writing to %s, size: %d bytes, value=%s"%(tmp1, size/8, tmp2))
        
        #set bytes in reversed positions (following the physical schema)
        for pos in range(0,size,8):
            self.state.memory[tmpstate] = self.state.solver.extractExpr(value, pos, pos+8-1)
            
            newtmpstate=self.state.solver.addExpr(tmpstate, self.state.solver.constExpr(1))
            if tmpstate != state:
                self.state.solver.deleteExpr(tmpstate)
            tmpstate=newtmpstate
        
        return True

    def getMemoryState(self, stateandsize):
        """
        given a 2-tuple (like the one generated by buildState), returns the memory state of that address (byte per byte)
        
        """

        state = stateandsize[0]
        size = stateandsize[1]
        if state[0] != 'mem':
            reason = "trying to get a Memory State from a non-memory reference"
            self.reportError(UnexpectedException, "Exception while analyzing '%s' at 0x%x: %s"%(self.lastDisasm, self.lastAddress, reason))
        
        tmpstate = self.transformMemoryStateToSolverState(state)
        return self.getMemoryStateFromSolverState(tmpstate, size)
    
    def getMemoryStateFromSolverState(self, state, size):
        """
        This function retrieves the value associated with the memory
        location denoted by state. The argument 'state' should be a
        simplified solver expression. The value associated with this
        'memory location' will also be a solver expression.

        If self.useCurrentMemory is in use, on the first access to an
        address, we read the actual value and associate it with state
        in our memory map. If not, a default variable expression would 
        instead be created. When doing symbolic execution this would 
        indicate the memory location is entirely under user control.

        @type state: Expression
        @param state: An expression denoting a memory location

        @type size: Int
        @param size: The size of the memory location in bits

        @rtype: Expression
        @return: The expression associated with the memory location
            denoted by state
        """

        tmpstate = state
        ret = []
        
        if self.useCurrentMemory:
            m_addr = self.getAddressFromState(state)                      
        
        #return the bytes positions reversed (following the physical position)
        for pos in range(0,size,8):
            if self.useCurrentMemory:
                addr = m_addr + (pos / 8)
                # If the address being accessed has never been set or
                # retrieved from before then we initialise it with the
                # actual value currently at that location in memory
                if not self.state.memory.has_key(tmpstate):
                    if self._debug:
                        self.imm.log("Reading mem: %08x"%addr, addr)
                    val = self.imm.readMemory(addr, 1)

                    if len(val) == 0:
                        #Error trying to read real memory
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
    
    def writeMemory(self, address, value):
        """
        address is an Expression
        value is an Expression
        """
        
        valsize=self.state.solver.getBitSizeFromExpr(value)
        
        size=((valsize+7)//8)*8 #rounded up to 8bits
        if valsize != size:
            value=self.state.solver.zeroExtendExpr(value, size)

        return self.setMemoryStateFromSolverState(address, value, size)

    def readMemory(self, address, size):
        return self.getMemoryStateFromSolverState(address, size*8)
    
    def transformMemoryStateToSolverState(self, state):
        """
        Take the output from buildState and make a Resolver representation of a memory index.
        """
        
        #init the temporary pseudo-register with the constant part of the address
        tmpstate = self.state.solver.constExpr(state[1][6])

        #add index1 * scale1 (if available)
        if state[1][0]:
            newtmpstate = self.state.solver.addExpr(tmpstate, self.state.solver.umulExpr(state[1][2], self.state.solver.constExpr(state[1][1]), 32))
            self.state.solver.deleteExpr(tmpstate)
            tmpstate=newtmpstate

        #add index2 * scale2 (if available)
        if state[1][3]:
            newtmpstate = self.state.solver.addExpr(tmpstate, self.state.solver.umulExpr(state[1][5], self.state.solver.constExpr(state[1][4]), 32))
            self.state.solver.deleteExpr(tmpstate)
            tmpstate=newtmpstate
        
        return tmpstate
    
    def buildState(self, op, opnum):
        """
        It builds a state representation of an operand.
        
        It takes an opCode class and the operator number (0-indexed) and returns a 2-tuple:
        ( state, size )
        
        Size is represented in bits
        """
        
        operand=op.operand[opnum]

        #unkknown type
        if operand[0] == DEC_UNKNOWN:
            reason = "DEC_UNKNOWN type"
            self.reportError(UnexpectedException, "Exception while analyzing '%s' at 0x%x: %s"%(self.lastDisasm, self.lastAddress, reason))
        
        #constant type
        elif operand[0] & DEC_CONST:
            return ( ( 'con', operand[3] ), operand[1]*8 )
        
        #memory access type
        elif not (operand[0] & DECR_ISREG):
            #not a constant and not a register ==> memory access
            
            index1=index2=""
            index1_scale=index2_scale=0
            index1_state=index2_state=0
            const=operand[3]
            
            #traverse the registers tuple looking for the indexes
            for reg in range(0,8):
                if operand[2][reg]:
                    if index1 == "":
                        index1 = Registers32BitsOrder[reg]
                        index1_scale = operand[2][reg]
                        index1_state = self.state.regs[index1]
                    else:
                        index2 = Registers32BitsOrder[reg]
                        index2_scale = operand[2][reg]
                        index2_state = self.state.regs[index2]
            
            #FS: segment fixup
            #if FS:, we get the TEB address and add that
            if "FS:" in op.result:
                const+=self.imm.getCurrentTEBAddress()
            
            return ( ( 'mem', (index1, index1_scale, index1_state, index2, index2_scale, index2_state, const) ), operand[1]*8 )
        
        #register type
        elif operand[0] & DECR_ISREG:
            for reg in range(0,8):
                if operand[2][reg]:
                    break
            
            if   operand[0] == DECR_DWORD:
                return ( ( 'reg', reg ), 32 )
            elif operand[0] == DECR_WORD:
                return ( ( 'reg', reg ), 16 )
            if   operand[0] == DECR_BYTE:
                return ( ( 'reg', reg ), 8 )
            else:
                #MMX/SSE/etc registers
                reason = "Unsupported register size"
                self.reportError(UnexpectedException, "Exception while analyzing '%s' at 0x%x: %s"%(self.lastDisasm, self.lastAddress, reason))
        
        #catch-all exception for any kind of weird errors
        reason = "unknown state type"
        self.reportError(UnexpectedException, "Exception while analyzing '%s' at 0x%x: %s"%(self.lastDisasm, self.lastAddress, reason))
