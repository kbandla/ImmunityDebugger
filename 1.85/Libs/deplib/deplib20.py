from x86smt.sequenceanalyzer import StateMachine
from x86smt.prettysolver import PrettySolver, Expression
from libgadgets import GadgetsDB, HashesDictionary, PropertiesDictionary
from immlib import *
from copy import deepcopy,copy
from vars import VAR

class deplibCompiler:
    def __init__(self):
        self.operations={}
        self.handlers={}
        self.cmdList=[]
        self.uses={}
        self.defines={}
        self.variables={}
        self.protectedVarsRegs={} # this is a dict using the same index that cmdList, vars/regs here should be considered protected
                                    # on command's ENTRANCE
        self.labels={}
        self.searchHandlers()

    ############### generic handlers management ###################
    def searchHandlers(self):
        tricks=__import__("deplib.tricks", globals(), locals(), "*")
        for modname in tricks.__all__:
            if hasattr(tricks, modname):
                mod = getattr(tricks, modname)
                if hasattr(mod, "init"):
                    mod.init(self)

    def register_operation(self, name, args_func=None):
        """
        Each registered operation must define a function that analyze the arguments coming
        from user and return a 3-tuple formated as:
        - arguments (a list or dict with the arguments as expected to be received by the operation's handlers)
        - used variables/registers
        - defined variables/registers

        We provide an standard arguments analyzer function, which returns:
        - a list of arguments in the same order than received
        - the first variable, set as defined
        - the rest, set as used

        This is the usual analysis for arithmetic/logical operations on INTEL order
        """

        if not args_func: args_func = self.standardArgs

        self.operations[name]=args_func

    def register_handler(self, opername, handler, pref):
        if not self.handlers.has_key(opername):
            self.handlers[opername] = {}
        if not self.handlers[opername].has_key(pref):
            self.handlers[opername][pref]=[]
        self.handlers[opername][pref].append(handler)

    def generic_handler(self, opername, *args, **kwargs):
        """
        This generic handler is here to create our commands list.
        Each command is a 3-tuple defined as:
        - Command's Name
        - Up to what node should we protect this command (for jumps back)
        - Arguments
        """

        tmp = self.operations[opername](self, *args, **kwargs)
        if tmp:
            for use in tmp[1]:
                if not self.uses.has_key(use):
                    self.uses[use]=[]
                self.uses[use].append(len(self.cmdList))

            for d in tmp[2]:
                if not self.defines.has_key(d):
                    self.defines[d]=[]
                self.defines[d].append(len(self.cmdList))

            self.cmdList.append( (opername, -1, tmp[0], tmp[1], tmp[2] ) )


    def protectCommands(self):
        """
        Analyze all jumps back and mark what commands need to be protected and up to what node should they be.

        """

        for i in xrange(0, len(self.cmdList)):
            name=self.cmdList[i][0]

            if name in [ 'jmp', 'ifeq', 'ifzero' ]:
                if name == 'jmp': jumpto = self.cmdList[i][2][0]
                if name == 'ifzero': jumpto = self.cmdList[i][2][1]
                if name == 'ifeq': jumpto = self.cmdList[i][2][2]
                try:
                    jumptoCmd=self.labels[jumpto]
                except KeyError:
                    raise Exception, "Tried to jump to an undefined label:%s"%jumpto

                if jumptoCmd <= i:
                    for n in xrange(jumptoCmd, i+1):
                        if self.cmdList[n][1] < i:
                            self.cmdList[n][1] = i

    def processDefUseChains(self):
        self.protectedVarsRegs={} #clean the dict for possible reuses
        
        for var,uses in self.uses.iteritems():
            for use in uses:
                #find last definition before current use
                define=None
                if self.defines.has_key(var):
                    for d in self.defines[var]:
                        if d < use and d > define:
                            define=d

                if define == None:
                    define = -1 #protect from the beginning of the cmdList

                for x in range(define+1, use+1):
                    if not self.protectedVarsRegs.has_key(x):
                        self.protectedVarsRegs[x]=[]
                    if var not in self.protectedVarsRegs[x]:
                        self.protectedVarsRegs[x].append(var)

    def setLocals(self, module):
        """
        set all operations in the local context provided, a nice trick for scripts.
        """

        setattr(module, "__myownself__", self)
        for name in self.operations.keys():
            setattr(module, name, eval("lambda *args, **kwargs: __myownself__.generic_handler('%s', *args, **kwargs)"%name))
        
        setattr(module, "newVar", self.newVar) #register new variables


    ############### Helpers for handlers ######################
    @staticmethod
    def standardArgs(self, *args, **kwargs):
        #we dont support arguments defined by name here, as they dont have a particular order
        if len(kwargs):
            raise Exception, "we cant support arguments defined by name in the standardArgs function"

        defined=[args[0]]
        if len(args) > 1:
            used=args[1:]
        else:
            used=[]

        return (args, used, defined)

    def newVar(self):
        tmp = VAR(self)
        self.variables[tmp.uniqid]=tmp
        return tmp

    ###########################################################


class DeplibFinder:
    def __init__(self, config=None, compiler_instance=None):
        """
        config is a dictionary of configuration parameters (see self.loadConfig).

        """

        self.hashes = None
        self.props = None
        self.memoryFlags = {}
        self.gadgets = {}
        self.rop = {}
        self.chunks = set()
        self.allocated = {}
        self.stack = []
        self.mode = ""
        self.rollbacks = [] #stack of decisions that we might rollback to try other options
        self.currentCommand = None

        #gadget searching SequenceAnalyzer instance
        self.sea = StateMachine(solver=PrettySolver())
        self.sea.push() #push the initial clean state on the search instance so we can move back to it without having to create a new one

        #current deplib state machine
        self.state = StateMachine(solver=PrettySolver())

        #defaults
        self.modules = None #Set this or it's going to fail... this's on purpose!
        self.badchars = ""
        self.stackpage = 0x1000
        self.bannedGadgets = []

        if config:
            self.loadConfig(config)

        if compiler_instance:
            self.processCommands(compiler_instance)

    def processCommands(self, compiler_instance):
        self.compilerInstance = compiler_instance
        self.compilerInstance.finderInstance = self     #we need to cross information

        compiler_instance.protectCommands()
        compiler_instance.processDefUseChains()

        cmdid=0
        self.currentRollback = None
        
        while cmdid < len(compiler_instance.cmdList):
            opername=cmd[0]
            args=cmd[2]
            ret=False
            
            self.currentCommand = { "id":cmdid, \
                                    "name":cmd[0], \
                                    "protectedvars":self.protectedVarsRegs[cmdid], \
                                    "protectedcmd":cmdid <= cmd[1], \
                                    "args":cmd[2], \
                                    "uses":cmd[3], \
                                    "defines":cmd[4] }
            self.updateGuarded() #this must be done in two steps as updateGuarded() uses information from this same dictionary.
            self.currentCommand["dependencies"]=self.updateVariableDependencies()

            if not compiler_instance.handlers.has_key(opername):
                raise Exception, "An operation was registered (%s) but no handler was"%opername

            prefs = compiler_instance.handlers[opername].keys()
            prefs.sort()
            for p in prefs:
                handlers = compiler_instance.handlers[opername][p][:] #get a copy
                
                while len(handlers):
                    handler=handlers.pop()
                    self.currentCommand["handlerid"]=id(handler)
                    self.cleanAfterHandlerOps()
                    level = self.push()
                    
                    ret=handler(self, args)
                    
                    if ret and self.processAfterHandlerOps():
                        break
                    
                    self.popto(level) #handler didnt work out at some point, revert everything to the previous state

                if ret: break
            if not ret:
                #if we are here, it means we didn't find any good handler
                origcmdid=cmdid
                cmdid = self.processRollbacks()
                if cmdid == None:
                    raise Exception, "Any of the available handlers worked out for '%s' on cmdid=%d"%(opername, origcmdid)
            else:
                cmdid+=1
                self.currentRollback = None

    def updateVariableDependencies(self):
        """
        a variable might point to memory pointed by another variable, so we must find those cases and solve them to give an accurate list to freeReg.
        """
        
        deps=set()
        for var in self.currentCommand["uses"] + self.currentCommand["defines"]:
            deps.union(self.__variable_dependencies_helper(var))
        
        return list(deps)
    
    def __variable_dependencies_helper(self, var):
        deps=set()
        if var.isMemBound():
            for x in range(0,2):
                if   var.containerValue[x][0][0] == "var":
                    deps.union(self.__variable_dependencies_helper(self.compilerInstance.variables[var.containerValue[x][0][1]]))
                elif var.containerValue[x][0][0] == "reg":
                    deps.add(var.containerValue[x][0][1])
                        
        return deps
                
    def processRollbacks(self):
        if len(self.rollbacks) < 1:
            return None
        
        tmp=self.rollbacks.pop()
        self.currentRollback={"cmdid":tmp[0], "handlerid":tmp[1], "varid":tmp[2], "tries":tmp[3]}
        
        return self.currentRollback["cmdid"]
                
    def cleanAfterHandlerOps(self):
        self.afterhandlerops = []
    
    def processAfterHandlerOps(self):
        """
        The only operation after handler that can be registered by now is move to memory
        Each operation is a 3-tuple:
        - mem (move to mem)
        - variable uniqid
        - final memory address/reg
        """
        for op in self.afterhandlerops:
            if op[0] == "mem":
                var=self.compilerInstance.variables[op[1]]
                if not var.moveToMemory(op[2]):
                    return False
        
        return True
    
    def getFreeRegisters(self):
        regs=["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"]
        if self.mode == "ROP":
            regs.remove("ESP")
        
        for var in self.compilerInstance.variables.values():
            if var.isRegBound():
                regs.remove(var.containerValue)
        
        for addr in self.allocated.keys():
            varnames = addr.varsnames()
            for var in varnames:
                try:
                    regs.remove(var)
                except:
                    pass
        
        return regs
    
    def freeReg(self, tries=None, forceReg=None):
        """
        Free a register that is not being used in the current command and is not in the tries list.
        """
        
        for var in self.compilerInstance.variables.values():
            if var.isRegBound() and \
               var not in self.currentCommand["uses"] and \
               var not in self.currentCommand["defines"] and \
               var not in self.currentCommand["dependencies"] and \
               (tries == None or var.containerValue not in tries) and \
               (forceReg == None or var.containerValue == forceReg):
                reg = var.containerValue
                if var.moveToMemory():
                    var.forcedReg = reg
                    self.currentCommand["guarded"].remove(reg)
                    return reg
        return False

    def getRollbackTries(self, var):
        if self.currentRollback and \
           self.currentRollback["cmdid"] == self.currentCommand["id"] and \
           self.currentRollback["handlerid"] == self.currentCommand["handlerid"] and \
           self.currentRollback["varid"] == var.uniqid:
            return self.currentRollback["tries"]
        return []
    
    def addRollback(self, var):
        """
        This is executed AFTER electing a register for a variable and is not used if getVar/bindVar is executed with a provided reg (there's no election there)
        """
        
        tries = self.getRollbackTries(var)
        tries += [var.contentValue]
        self.rollbacks.append( (self.currentCommand["id"], self.currentCommand["handlerid"], var.uniqid, tries) )

    def solveMemoryExpression(self, indexedMemExpression):
        """
        Returns a single expression that represents the memory offset that a variable is pointing to.
        
        """
        
        idx0 = indexedMemExpression[0]
        idx1 = indexedMemExpression[1]
        const = indexedMemExpression[2]
        
        finalvalue = self.state.solver.constExpr(0)

        if const: finalvalue += const
        
        for idx in (idx0, idx1):
            if idx[0][0] == "notused" or idx[1] == 0:
                continue
            if idx[0][0] == "reg":
                finalvalue += self.state.solver.lookupVar(idx[0][1])[0] * idx[1]
            elif idx[0][0] == "var":
                var = self.compilerInstance.variables[idx[0][1]]
                if not var.isBound(): 
                    raise Exception, "you're trying to use an unbound/unset variable as a memory index"
                reg = var.getVar()
                if not reg:
                    return False
                finalvalue += self.state.solver.lookupVar(reg)[0] * idx[1]
        
        return finalvalue
    
    def loadConfig(self, config):
        """
        Receives a dictionary of parameters:
        - modules:   a list of either module IDs, module name or 2-tuples with module name and version
                     Default: None (MANDATORY PARAMETER)
        - badchars:  a list of characters not allowed in the generated ROP
                     Default: ""
        - roparea:   A 2-tuple with the initial address of the user controlled space where EIP points to, and the size of this area as a second element
                     Default: (ESP, 0x1000)
        - stackpage: size in bytes of the current stack (stack is considered to be writable and some gadget could overwrite non-protected areas)
                     Default: 0x1000
        - memory:    A list of 3-tuples with: Initial Address, Size and Permission (see self.setMemFlags)
                     Initial address can be a numeric address, an expression's dump or a Expression instance.
                     Default: None
        - initstate: A dictionary used to initialize the state of the ROP machine.
                     Keys are regs/flags/mem address as used in a SequenceAnalyzer instance, values are dumped expressions (see Solver.dumpExpr)
                     Memory addresses are expressed as expression dumps too (not MEM<CRC32>).
                     This are values that are known to be always precise. Run-dependant values (like object addresses) should be avoided.
                     Default: None
        - banned:    A list of banned gadgets that we can't use. Each gadget is a 2-tuple with module_id and offset.
        - DB related parameters:
          - dbtype: sqlite3/mysql (Default: sqlite3)
          - dbname                (Default: gadgets.sq3 if sqlite3 or gadgets)
          - username
          - passwd
          - host                  (Default: 127.0.0.1)

        """

        args={"dbtype":None, "dbname":None, "host":None, "username":"", "passwd":""}
        for k in args.keys():
            if config.has_key(k) and config[k] != None: args[k]=config[k]
        args["quiet"]=True
        self.gdb = GadgetsDB(None, **args)

        if config.has_key("modules"):
            mods=config["modules"]

            self.modules = self.gdb.get_module_ids(mods)

            self.bases = self.gdb.get_module_base_from_id(self.modules)

            self.hashes = HashesDictionary(self.gdb, self.modules)

            self.props = PropertiesDictionary(self.gdb, self.modules)

        if config.has_key("badchars"):
            self.badchars = config["badchars"]

        if config.has_key("stackpage"):
            self.stackpage = config["stackpage"]

        if config.has_key("banned"):
            self.bannedGadgets = config["banned"]

        if not self.setMemFlags(self.state.regs["ESP"], self.stackpage, "RW"):
            raise Exception, "There was some error setting the initial permissions for the stack page. Check your 'memory' configuration and the stack page size."

        if config.has_key("memory"):
            for mem in config["memory"]:
                self.setMemFlags(mem[0], mem[1], mem[2])
        
        if config.has_key("roparea"):
            addr=config["roparea"][0]
            size=config["roparea"][1]
        else:
            addr=self.state.regs["ESP"]
            size=0x1000
        
        if not self.setMemFlags(addr, size, "RWA"):
            raise Exception, "ROP Area configuration is wrong"

        if config.has_key("initstate"):
            for k,v in config["initstate"].iteritems():
                if k in self.state.regs.keys():
                    self.state.regs[k]=self.state.solver.loadExpr(v)
                elif k in self.state.flags.keys():
                    self.state.flags[k]=self.state.solver.loadExpr(v)
                else:
                    self.state.memory[k]=self.state.solver.loadExpr(v)
        else:
            #set a default initial state suitable for ROP (emulate a RETN)
            EIP=self.readMemory(self.state.regs["ESP"], 4, "R")
            self.state.regs["ESP"]+=4
            self.state.EIP=EIP
        
        #detect Branching Oriented Programming main mode
        
        #EIP is supposed to be pointing to user controlled space
        #If EIP is pointing to memory indexed by ESP, we use ROP, JOP otherwise.
        ptr = self.getEIPptr()
        if "ESP" in ptr.varsnames():
            self.mode = "ROP"
        else:
            self.mode = "JOP"


    def addressToExpression(self, addr):
        if isinstance(addr, int) or isinstance(addr, long):
            #numeric address
            addr=self.state.solver.constExpr(addr)
        elif isinstance(addr, tuple):
            #expression's dump
            addr=self.state.solver.loadExpr(addr)
        elif isinstance(addr, str) and self.state.regs.has_key(addr.upper()):
            #is a register
            addr=self.state.regs[addr.upper()]

        if not isinstance(addr, Expression):
            raise Exception, "Memory Address is not an Expression's instance (is a %s)"%type(addr)

        addr.simplify()
        return addr

    def setMemFlags(self, addr, size, flags):
        """
        addr is either a numeric address, an expression's dump or an Expression instance.
        perm is: (read access is always granted if it has any other flag set, unless "N" is set):
          - R: read access
          - W: write access
          - P: this byte is part of the generated ROP
          - G: this byte is part of a gadget's address
          - S: this byte is a spare byte added to the ROP to align it (it doesn't matter what value it has, as long as it pass the badchars checks)
          - A: this byte is part of the ROP area (the user controlled piece of memory where our ROP is stored), mutually exclusive with P.
          - F: a perm can change to any other state until the F flag is set, which means the permissions for this memory byte cannot be changed anymore
          - B: Part of a ROP allocation (busy byte)
          - N: NO ACCESS

        NOTE: Always check the return from setMemFlags, if it fails, it returns False without touching anything.

        """

        addr=self.addressToExpression(addr)
        addr.simplify()

        for x in xrange(0, size):
            tmp = addr+x
            tmp.simplify()
            if self.memoryFlags.has_key(tmp) and "F" in self.memoryFlags[tmp]:
                return False
        
        if not self.memoryFlags.has_key(addr):
            self.chunks.add( (addr, size) )

        if "R" not in flags and "N" not in flags:
            flags+="R"

        for x in xrange(0, size):
            tmp = addr+x
            tmp.simplify()
            self.memoryFlags[tmp]=flags

        return True

    def checkMemAccess(self, addr, perm, size=1):
        """
        check a given addr over our memory flags.

        addr is either a numeric address, an expression's dump or an Expression instance.
        """

        addr=self.addressToExpression(addr)

        for x in xrange(0, size):
            tmp = addr+x
            tmp.simplify()
            if not self.memoryFlags.has_key(tmp):
                return False
            p=self.memoryFlags[tmp]
            if "N" in p:
                return False
            if perm not in p:
                return False

        return True

    def readMemory(self, addr, size=1, perms="R"):
        """
        If readMemory returns False, it means that at least one of the bytes requested for read access was not permited.

        """

        addr=self.addressToExpression(addr)
        if not self.checkMemAccess(addr, perms, size):
            return False

        return self.state.readMemory(addr, size)

    def writeMemory(self, addr, value, perms):
        """
        value size is determined automatically.

        Always check the return from writeMemory, as it might fail if the current permissions dont allow updates over a given address.

        It returns False on error or True if everything went well.
        """

        addr=self.addressToExpression(addr)
        addr.simplify()

        size = (len(value)+7)//8
        if not self.setMemFlags(addr, size, perms): #first set memory flags to fail here, before modifying anything.
            return False

        value.zeroExtend(size*8) #we store complete bytes in memory
        
        if "G" in perms: #save gadget addresses for later use
            self.gadgets[addr] = value

        for x in range(0, size):
            tmp = value[x*8:(x+1)*8]
            self.state.memory[addr] = tmp
            if "P" in perms:
                self.rop[addr] = tmp #if this is part of the ROP, make a clean copy for later use :)
            addr+=1

        return True
    
    def alloc(self, bytes, useRelativeAddresses=False):
        """
        Small ROP allocator function. It takes the information from the memoryFlags dictionary to find a free chunk suitable for use and returns its address.
        
        For this allocator we only use absolute addresses, a useRelativeAddresses flag is there that allow non-absolute addresses, but keep in mind that 
        the memory indexes must be guarded as long as you want access to your allocated memory.
        
        """
        
        for addr,size in self.chunks:
            varsnames=addr.varsnames()
            if not useRelativeAddresses and len(varsnames) > 0:
                continue
            
            for pos in range(0, size):
                cur=addr+pos
                cur.simplify()
                if self.checkMemAccess(cur, "W", bytes) and \
                   not self.checkMemAccess(cur, "F", bytes) and \
                   not self.checkMemAccess(cur, "P", bytes) and \
                   not self.checkMemAccess(cur, "A", bytes) and \
                   not self.checkMemAccess(cur, "S", bytes) and \
                   not self.checkMemAccess(cur, "B", bytes):
                    
                    #set bytes as busy and remove writeable flag
                    for x in range(0, bytes):
                        tmp = cur+x
                        tmp.simplify()
                        flags=self.memoryFlags[tmp].replace("W","") #remove W
                        flags+="B" #add B
                        
                        self.setMemFlags(tmp, 1, flags)
                    
                    self.allocated[cur]=bytes
                    
                    return cur
    
    def free(self, addr):
        """
        Free an allocated piece of memory by removing the B flag and reseting the W flag.
        
        """
        
        addr.simplify()
        if not self.allocated.has_key(addr):
            return False
        
        bytes = self.allocated.pop(addr)
        
        for x in range(0, bytes):
            tmp = addr+x
            tmp.simplify()
            flags=self.memoryFlags[tmp].replace("B","") #remove B
            flags+="W" #add W
            
            self.setMemFlags(tmp, 1, flags)
        
        return True

    def push(self):
        """
        Pushes the state of the deplib finder.

        Returns the stackLevel where the state was saved.
        """

        self.state.push()

        #deepcopying, except variables where we must avoid copy recursion
        tosave = ( copy(self.gadgets), deepcopy(self.memoryFlags), deepcopy(self.rop), deepcopy(self.chunks), deepcopy(self.allocated), copy(self.compilerInstance.variables), deepcopy(self.currentCommand) )

        self.stack.append(tosave)
        return len(self.stack) - 1

    def pop(self):
        self.state.pop()

        ret = self.stack.pop()
        ( self.gadgets, self.memoryFlags, self.rop, self.chunks, self.allocated, self.compilerInstance.variables, self.currentCommand ) = ret

        return ret

    def popto(self, stackLevel):
        ret=None
        while len(self.stack) > stackLevel:
            ret=self.pop()
        return ret

    def stacklevel(self):
        return len(self.stack)

    def cleanSearch(self):
        """
        clean the search state machine by popping and pushing the orig state
        """
        self.sea.popto(0)
        self.sea.push()


    ################## gadget's searching #####################
    def findGadget(self, mode=1, allresults=False):
        """
        Search for a gadget that complies with all constrains given in self.sea.
        It also has to comply with constrains in guarded (regs/flags/mem) and to have
        some standard properties like controlled ESP and EIP.

        First it tries using the hashes dictionary and if it cant find a match, 
        it searchs on the DB using first the properties value and then instantiating each
        gadget and quering the solver.

        mode is a bitmask that decides if we search by hashes (=1) and/or by props(=2)

        This is an iterator that returns a 4-tuple (modid, offset, addedcomplexity, mode) of the chosen gadget.
        """

        self.sea.simplify()
        searchHashes=self.sea.hashState()

        tmp=self.sea.calcProperties()

        searchProps={}
        for k,v in tmp[0].iteritems():
            if v: searchProps[k]=v
        if tmp[1]:
            searchProps["FLAGS"]=(tmp[1], tmp[1]) #we only care about the flags that changed

        findings=[]

        #first search by hashes and then by properties
        #each search is ordered by module and complexity (it respects module order from self.modules)
        if mode & 1:
            by_hashes=self.gdb.search_by_hashes(searchHashes, self.hashes)
            generator=self.findBestGadget(by_hashes, mode=1)
            for gadget in generator:
                if tuple(gadget) not in findings:
                    findings.append(tuple(gadget))
                    gadget.append(1)
                    yield gadget
                    if not allresults:
                        break

            generator.close()

        if mode & 2:
            by_props=self.gdb.search_by_properties(searchProps, self.props)
            generator=self.findBestGadget(by_props, mode=2)
            for gadget in generator:
                if tuple(gadget) not in findings:
                    findings.append(tuple(gadget))
                    gadget.append(2)
                    yield gadget
                    if not allresults:
                        break

            generator.close()

    def findBestGadget(self, generator, mode):
        """
        It tries to find the gadget with the lower added complexity from the gadget's generator provided.

        This function is an iterator. Which is useful for returning all best matches.
        """

        bestMatch = None

        for candidate in generator:
            complexity = candidate[2]

            if bestMatch and complexity > bestMatch[2]:
                yield bestMatch
                bestMatch = None

            addedcomplexity = self.applyGadget(candidate, mode=mode, dryRun=True)
            if addedcomplexity == None:
                continue
            addedcomplexity += complexity #add the complexity of the chosen gadget to have a number that represents the whole bunch

            #if we are here, it means we found a match
            if not bestMatch or addedcomplexity < bestMatch[2]:
                bestMatch = [candidate[0], candidate[1], addedcomplexity]

        if bestMatch:
            yield bestMatch

    def applyGadget(self, gadget, mode=1, recursiveEnter=False, dryRun = False):
        """
        This function might destroy the state of the ROP, so please remember to push/pop before using it.

        Returns the added complexity resulting from using a given gadget or None if it's not possible to apply.
        """

        modid = gadget[0]
        offset = gadget[1]

        #we cant use banned gadgets
        if (modid, offset) in self.bannedGadgets:
            return None

        gadget_sm = self.gdb.get_gadget_by_offset(modid, offset)
        address = self.bases[modid] + offset
        newcomplexity = 0

        ret = self.checkPreconditions(gadget_sm, address, mode)
        if ret == 0:
            return None #it's impossible to apply this gadget

        if ret == 1:
            if recursiveEnter:
                return None

            if dryRun:
                level=self.push() #save the current state before any modification

            newcomplexity = self.fixPreconditions(gadget_sm, mode)

            if dryRun:
                self.popto(level)

            if newcomplexity == None: #it was impossible to fix the preconditions
                return None

        #if we are here, it's because we can use this gadget, so we update the state machine and self.memoryFlags to reflect this change.
        if not dryRun:
            #mark mem address as ROP and write it to the state memory
            EIPptr=self.getEIPptr()

            perms="RPG"
            if self.currentCommand["protectedcmd"]:
                perms+="F" #if this is a protected operation, gadget's address cannot be overwritten

            address = self.state.solver.constExpr(address)
            self.writeMemory(EIPptr, address, perms)

            #merge the changes from the added gadget
            self.state.mergeState(gadget_sm)
            self.state.simplify()

        return newcomplexity

    def getEIPptr(self):
        tmp=self.state.EIP[0:8]
        tmp.simplify()
        tmp=self.state.memory.sources[str(tmp).replace("VAL","MEM")]
        return self.state.solver.loadExpr(tmp)

    def checkPreconditions(self, gadget, address, mode):
        """
        Check if we can use this gadget and return an integer that means:
        - 0: we cant use this gadget
        - 1: we can use this gadget after applying fixes from fixPreconditions
        - 2: we can use this gadget as it is right now

        Note: this function only CHECK things, NEVER changes the machine state

        if it returns 1:
            It saves a list of fixes that must be applied to the gadget in order to be useful.
            This fixes are correct as long as the machine state remains the same and the gadget remain the same.

        Conditions:
        - Each byte of EIP must be a VALxxxxxxxx pointing to 4 sucessives bytes in memory
        """

        #self.fixes[hash(self.state)][hash(gadget)]=["fixes"]
        #XXX: TODO

        return 2

    def fixPreconditions(self, gadget, mode):
        """
        Try to fix the current state machine so we can use the given gadget.

        It returns the added complexity for all the added gadgets or None if the problem is unfixable.

        Note: this function CHANGES the machine state.
        """

        return 0

        #XXX: TODO
        #XXX: call applyGadget with recursiveEnter=True

    
    ################################# Variables handling ############################################
    def updateGuarded(self):
        """
        return a list of guarded registers and other information that needs to be protected.
        
        """
        
        guarded = []
        for var in self.currentCommand["protectedvars"]:
            if var.isRegBound():
                guarded.append(var.containerValue)
        
        self.currentCommand["guarded"] = guarded

    
    ################################### Utilities ###################################################
    def checkBadChars(self, tocheck):
        return True
        #XXX: TODO
        
        
    def moveExprToReg(self, exp, reg=None):
        """
        Move an expression to a register.
        
        Returns the register where the expression was set.
        """
        
        mergeDict = {}
        mergeDict.update(self.state.regs)
        mergeDict.update(self.state.flags)
        mergedExpr = exp.merge(mergeDict)
        
        freeregs=self.getFreeRegisters() #if we're gonna change something, we can only use free registers
        allregs=self.state.regs.keys()
        if reg:
            ROregs=[reg] #we can just use this one
            RWregs=[reg]
            TMPregs=freeregs
        else:
            ROregs=allregs #if it doesnt imply changing the content of the register, we can use any register
            RWregs=freeregs
            TMPregs=freeregs
        
        if not self.currentCommand["protectedcmd"]: #protected cmds cannot use CONTEXT for searchs
            #first check if some of the registers have the given value, just by chance.
            for tmp in ROregs:
                if self.state.regs[tmp] == mergedExpr:
                    return tmp
        
        #MOV REG, EXP
        bestcomplexity=None
        for tmp in RWregs:
            self.cleanSearch()
            self.sea.regs[tmp] = exp
            for g in self.findGadget():
                if not bestcomplexity or g[2] < bestcomplexity[1][2]:
                    bestcomplexity=(tmp,g)
                    
        if bestcomplexity:
            if self.applyGadget(bestcomplexity[1]) == None:
                raise Exception, "Shouldn't happen"
            return bestcomplexity[0]
        
        if not self.currentCommand["protectedcmd"] and mergedExpr.isConstant() and mergedExpr != exp: #protected cmds cannot use CONTEXT for searchs
            #MOV REG, MERGED_EXP
            bestcomplexity=None
            for tmp in RWregs:
                self.cleanSearch()
                self.sea.regs[tmp] = mergedExpr
                for g in self.findGadget():
                    if not bestcomplexity or g[2] < bestcomplexity[1][2]:
                        bestcomplexity=(tmp,g)
                        
            if bestcomplexity:
                if self.applyGadget(bestcomplexity[1]) == None:
                    raise Exception, "Shouldn't happen"
                return bestcomplexity[0]
            
            #Check if there's a simple operation that ends in our desired value using the current CONTEXT
            #SUB|ADD|etc REG, TMP (CONTEXT)
            bestcomplexity=None
            for r in RWregs:
                for tmp in allregs: #this secondary reg is used RO
                    tri=[]
                    if self.state.regs[r] + self.state.regs[tmp] == mergedExpr:
                        tri.append("add")
                    if self.state.regs[r] - self.state.regs[tmp] == mergedExpr:
                        tri.append("sub1")
                    if self.state.regs[tmp] - self.state.regs[r] == mergedExpr:
                        tri.append("sub2")
                    if (self.state.regs[r] * self.state.regs[tmp])[0:32] == mergedExpr:
                        tri.append("mul")
                    if self.state.regs[r] / self.state.regs[tmp] == mergedExpr:
                        tri.append("div1")
                    if self.state.regs[tmp] / self.state.regs[r] == mergedExpr:
                        tri.append("div2")
                    
                    for t in tri:
                        self.cleanSearch()
                        if   t == "add":
                            self.sea.regs[r] += self.sea.regs[tmp]
                        elif t == "sub1":
                            self.sea.regs[r] = self.sea.regs[r] - self.sea.regs[tmp]
                        elif t == "sub2":
                            self.sea.regs[r] = self.sea.regs[tmp] - self.sea.regs[r]
                        elif t == "mul":
                            self.sea.regs[r] = (self.sea.regs[r] * self.sea.regs[tmp])[0:32]
                        elif t == "div1":
                            self.sea.regs[r] = self.sea.regs[r] / self.sea.regs[tmp]
                        elif t == "div2":
                            self.sea.regs[r] = self.sea.regs[tmp] / self.sea.regs[r]
        
                        for g in self.findGadget():
                            if not bestcomplexity or g[2] < bestcomplexity[1][2]:
                                bestcomplexity=(r,g)
                                
            if bestcomplexity:
                if self.applyGadget(bestcomplexity[1]) == None:
                    raise Exception, "Shouldn't happen"
                return bestcomplexity[0]
        
        if self.mode == "ROP":
            if exp.isConstant() or (mergedExpr.isConstant() and not self.currentCommand["protectedcmd"]):
                if exp.isConstant():
                    useexp = exp
                else:
                    useexp = mergedExpr
                
                if self.checkBadChars(useexp):
                    #POP REG
                    bestcomplexity=None
                    for r in RWregs:
                        self.cleanSearch()
                        self.sea.regs[r] = self.sea.readMemory(self.sea.regs["ESP"], 4)
                        for g in self.findGadget(mode=3): #do a search by properties too
                            gadget_sm = self.gdb.get_gadget_by_offset(g[0], g[1])
                            tmpreg  =gadget_sm.regs[r]
                            bytes=[]
                            for x in range(0, 32, 8):
                                b = gadget_sm.solver.simplify(gadget_sm.solver.extractExpr(tmpreg, x, x+7))
                                b = gadget_sm.solver.exprString(b).replace("VAL","MEM")
                                if b in bytes:
                                    break
                                bytes.append(b)
                            
                            if len(bytes) != 4:
                                continue #it should be composed of 4 different bytes, all coming from unsolved memory areas
                            
                            itsok=True
                            if g[3] == 2:
                                #search-by-properties gadget, check if it actually have a format that we can handle
                                for b in bytes:
                                    if not gadget_sm.memory.sources.has_key(b):
                                        itsok=False
                                        break
                                    if gadget_sm.memory.getIndexes(b, recursive=False) != set(["ESP"]): #it should be memory indexed by ESP ONLY
                                        itsok=False
                                        break
                                
                            if itsok:
                                if not bestcomplexity or g[2] < bestcomplexity[1][2]:
                                    bestcomplexity=(r,g,bytes,gadget_sm)
                                    
                    if bestcomplexity:
                        bytes=bestcomplexity[2]
                        gadget_sm=bestcomplexity[3]
                        bytes.reverse() #little endian
                        c=0
                        for b in bytes: #set memory before applying the gadget
                            tmp = self.state.solver.loadExpr(gadget_sm.memory.sources[b])
                            merged =tmp.merge(mergeDict)
                            perms="RP"
                            if self.currentCommand["protectedcmd"]:
                                perms+="F"
                            self.writeMemory(merged, useexp[c:c+8], perms)
                            c+=8
                            
                        if self.applyGadget(bestcomplexity[1]) == None:
                            raise Exception, "This shouldn't happen"
                        return bestcomplexity[0]
        
                #POP TMP|REG/SUB|ADD REG, TMP (CONTEXT)
                
        
        #POP REG/POP TMP/SUB|ADD REG, TMP
            
        #XXX: TODO
            
    def __find_good_op_chars(self, op, C, A=None, B=None):
        """
        find a pair of values so that doing A <operation> B = C.
        
        Where A and B are assured to be outside the badchars blacklist.
        """
        
        pass
    
        #XXX: TODO
    
