"""
Variables are always DWORD size (on x86 processors)

"""

import random

class VAR:
    def __init__(self, compiler=None):
        self.containerType = None
        self.containerValue = None
        self.compilerInstance = compiler
        self.uniqid = random.randint(0, 0xffffffff)
        self.forcedReg = None
        self.allocatedMem = False

    def release(self):
        self.containerType = None
        self.containerValue = None

    def bind(self, containerType, value):
        """
        Bind a variable to a real container (a reg or a mem area)
        containerType == reg/mem
        value = if type == reg: Register Name
                if type == mem: a tuple with:
                  ([index1, index1factor], [index2, index2factor], constant)
                  it accept smaller versions, ex:
                  EAX, ([EAX,2]), (someVAR, 2), (EAX,[EBX,4]), (EAX,[EBX,4], 0xcafe)
                if type == memexp: direct Expression (as returned by finder.alloc() for example)
        """
        
        if   containerType == "reg":
            self.containerType = "reg"
            self.containerValue = value.upper()
        elif containerType == "mem":
            indexes=[]
            constant = 0
            
            #normalize input
            if isinstance(value, str):
                indexes.append( (("reg", value.upper()), 1) )
            elif isinstance(value, int) or isinstance(value, long):
                constant=value & 0xffffffff
            elif isinstance(value, list) or isinstance(value, tuple):
                for part in value:
                    if isinstance(part, str):
                        indexes.append( (("reg", part.upper()), 1) )
                    elif isinstance(part, int) or isinstance(part, long):
                        constant=part & 0xffffffff
                    elif isinstance(part, list) or isinstance(part, tuple):
                        if isinstance(part[0], str):
                            indexes.append( (("reg", part[0].upper()), part[1]) )
                        else:
                            indexes.append( (("var", part[0].uniqid), part[1]) )
                    elif isinstance(part, VAR):
                        indexes.append( (("var", part.uniqid), 1) )

            elif isinstance(value, VAR):
                indexes.append( (("var", value.uniqid), 1) )
            else:
                return False
            
            if len(indexes) > 2:
                return False
            if len(indexes) < 2:
                indexes.append( (("notused",), 0) )
            
            self.containerType = "mem"
            self.containerValue = ( indexes[0], indexes[1], constant )
        elif containerType == "memexp":
            self.containerType = "memexp"
            self.containerValue = value.dump() #save the dump, not the expression itself as we want to use copy() with this object and get a complete copy (without aliasing).
        else:
            raise Exception, "Unknown container type"
            
        return True
    
    def isRegBound(self):
        return self.containerType == "reg"

    def isMemBound(self):
        return self.containerType == "mem"
    
    def isMemExpBound(self):
        return self.containerType == "memexp"
    
    def isBound(self):
        return self.containerType != None
    
    def getVar(self, reg=None, bindOnly=False):
        """
        Bind variables to registers or memory addresses.
        
        It returns the register name where the variable should be located.
        
        if reg is provided, use that instead of finding a free register.
        
        if container == null: allocate a free register.
        elif container == reg: use that
        elif container == mem/memexp: do a moveToReg and register a moveToMem operation after the handler has finished.
        
        IF bindOnly, then this rules are used instead:
          if container == null: allocate a free register.
          elif container == reg: use that
          elif container == mem/memexp: allocate a free register and register a moveToMem operation after the handler has finished.
        
        
        This function can retrieve a value from memory if needed or even change the container register.
        
        This function is rollback-aware and must obey the options presented by it.
        
        If the function fails, it returns False.
        """
        
        if reg: reg=reg.upper()
        tries=self.compilerInstance.finderInstance.getRollbackTries(self)
        freeregs = self.compilerInstance.finderInstance.getFreeRegisters()
        for r in tries:
            try:
                freeregs.remove(r)
            except:
                pass
        
        if reg in tries or self.forcedReg in tries: #refuse to bind a var to an already tried option
            return False
        
        if not reg and self.forcedReg:
            if self.forcedReg not in freeregs: #if we MUST bind to a particular reg (because we come from a moveToMemory generated by a freeReg() call, and we CANT free that reg, then we can't solve it.
                if not self.compilerInstance.finderInstance.freeReg(forceReg=self.forcedReg):
                    return False
                freeregs += [self.forcedReg] #now our forced register is free
            reg = self.forcedReg
        
        if reg:
            if reg not in freeregs:
                return False
            
            if self.containerType == None:
                self.containerType="reg"
                self.containerValue=reg
                self.forcedReg=None
                return reg
            
            elif self.containerType == "reg":
                if reg != self.containerValue:
                    if bindOnly:
                        self.containerValue=reg
                    elif not self.moveToReg(reg):
                        return False
                self.forcedReg=None
                return reg
            
            elif self.containerType == "mem" or self.containerType == "memexp":
                value=self.containerValue
                if bindOnly:
                    self.containerType="reg"
                    self.containerValue=reg
                else:
                    if not self.moveToReg(reg):
                        return False
                
                if not self.forcedReg: #if we're not part of a revert action from a moveToMemory, then append a revert action to memory.
                    self.compilerInstance.finderInstance.afterhandlerops.append( ("mem",self.uniqid,value) )
                else:
                    if self.allocatedMem: #free previously allocated memory, as we're not returning this variable to memory
                        self.compilerInstance.finderInstance.free(value)
                        self.allocatedMem=False
                    
                self.forcedReg=None
                return reg
        
        else:
            if self.containerType == None:
                if len(freeregs) == 0:
                    tmp=self.compilerInstance.finderInstance.freeReg(tries=tries)
                    if not tmp:
                        return False
                        
                    self.containerType="reg"
                    self.containerValue=tmp
                    self.compilerInstance.finderInstance.addRollback(self)
                    return tmp
                else:
                    self.containerType="reg"
                    self.containerValue=freeregs.pop()
                    self.compilerInstance.finderInstance.addRollback(self)
                    return self.containerValue
            
            elif self.containerType == "reg":
                return self.containerValue
            
            elif self.containerType == "mem" or self.containerType == "memexp":
                value=self.containerValue
                while len(freeregs):
                    tmp=freeregs.pop()
            
                    if bindOnly:
                        self.containerType="reg"
                        self.containerValue=tmp
                    elif not self.moveToReg(tmp):
                        continue
                    
                    #we found a winner register!
                    self.compilerInstance.finderInstance.addRollback(self)
                    self.compilerInstance.finderInstance.afterhandlerops.append( ("mem",self.uniqid,value) )
                    return tmp
                
                #backup mechanism, try to free a register and use it (do it only once)
                tmp=self.compilerInstance.finderInstance.freeReg(tries)
                if not tmp:
                    return False
                
                if bindOnly:
                    self.containerType="reg"
                    self.containerValue=tmp
                elif not self.moveToReg(tmp):
                    return False
                self.compilerInstance.finderInstance.addRollback(self)
                self.compilerInstance.finderInstance.afterhandlerops.append( ("mem",self.uniqid,value) )
                return tmp
        
        return False #it shouldn't get here ever
    
    def bindVar(self, reg=None):
        """
        Bind a variable to a free register but only for defining it, CONTENT SHOULD NOT BE TRUSTED.
        
        if reg is provided, use that instead of finding a free register.
        
        This function is rollback-aware and must obey the options presented by it.
        
        If the function fails, it returns False.
        """
        
        return self.getVar(reg=reg, bindOnly=True)
    
    def moveToReg(self, reg):
        pass
    
    def moveToMemory(self, memexpression=None):
        """
        Moves a variable to memory, it eithers alloc new memory or uses the provided memory address expression.
        
        Note: This can be only used after setting an associated finder instance to the compiler.
        
        memexpression can be an Expression instance, or a 3-tuple as described for the "mem" container type.
        """
        
        if self.containerType == "mem" or self.containerType == "memexp" and memexpression == None:
            return True #we are already in memory and we werent asked to change the location
        
        if self.containerType != "reg":
            reg = self.getVar()
            if not reg:
                return False

        if memexpression == None:
            self.allocatedMem = True
            memexpression = self.compilerInstance.finderInstance.alloc(4)
        elif isinstance(memexpression, tuple):
            memexpression=self.compilerInstance.finderInstance.solveMemoryExpression(memexpression)
            
        for memreg in self.compilerInstance.finderInstance.getFreeRegisters():
            self.compilerInstance.finderInstance.cleanSearch()
            
        
        #XXX: TODO, the part that actually moves the register to memory and updates its containertype and value
            