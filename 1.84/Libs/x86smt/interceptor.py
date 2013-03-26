"""
This functions let us intercept a function call (or a part of a function)
"""

class FunctionInterceptor:
    calleeclean = False
    protectedregs=["EBX","ESI","EDI","EBP"]
    returnreg = "EAX"
    
    def __init__(self, address, name, argc, emulator):
        self.address=address
        self.name=name
        self.argc=argc
        self.emulator=emulator
    
    def getArgs(self):
        #get the function argument from a symbolic machine according to a given calling convention
        pass
    
    def cleanStack(self):
        self.sa.state.regs['ESP'] = self.sa.state.solver.addExpr(self.sa.state.regs['ESP'], self.sa.state.solver.constExpr(self.argc * 4))
    
    def run(self, sa):
        """
        receives a sequence analyzer instance.
        """
        
        self.sa=sa
        args=self.getArgs()
        if self.emulator(self, args) == True: 
            #emulator must return TRUE if we should follow usual cleaning and return steps, otherwise the emulator itself
            #should change EIP and stack accordingly
            self.sa.state.EIP = self.sa.getMemoryStateFromSolverState(self.sa.state.regs['ESP'], 32) #emulate RETN
            self.sa.state.regs['ESP'] = self.sa.state.solver.addExpr(self.sa.state.regs['ESP'], self.sa.state.solver.constExpr(4))

            #remove this function from the callstack
            if len(self.sa.state.callstack):
                self.sa.state.callstack.pop()
            
            if self.calleeclean:
                #if the calling convention says the callee has to clean it
                self.cleanStack()
        
        del self.sa
        return True #it returns True to tell the emulation loop that we took care of this instruction

class CUSTOMFunctionInterceptor:
    def __init__(self, address, name, emulator):
        self.address=address
        self.name=name
        self.emulator=emulator
        
    def run(self, sa):
        """
        receives a sequence analyzer instance and gives it to the emulation callback.
        """
        
        return self.emulator(sa)

class CDECLFunctionInterceptor(FunctionInterceptor):
    args = ["stack"]
    
    def getArgs(self):
        args=[]
        tmp=self.sa.state.solver.addExpr(self.sa.state.regs['ESP'], self.sa.state.solver.constExpr(4)) #[ESP+4] == arg0
        for x in range(0, self.argc):
            args.append(self.sa.getMemoryStateFromSolverState(tmp, 32))
            tmp = self.sa.state.solver.addExpr(tmp, self.sa.state.solver.constExpr(4))
        
        return args

class STDCALLFunctionInterceptor(CDECLFunctionInterceptor):
    calleeclean = True

class FASTCALLFunctionInterceptor(FunctionInterceptor):
    args = ["ECX","EDX","stack"]
    calleeclean = True
    
    def getArgs(self):
        args=[]
        if self.argc > 0:
            args.append(self.sa.state.regs["ECX"])
            if self.argc > 1:
                args.append(self.sa.state.regs["EDX"])
                if self.argc > 2:
                    tmp=self.sa.state.solver.addExpr(self.sa.state.regs['ESP'], self.sa.state.solver.constExpr(4)) #[ESP+4] == arg0
                    for x in range(0, self.argc-2):
                        args.append(self.sa.getMemoryStateFromSolverState(tmp, 32))
                        tmp = self.sa.state.solver.addExpr(tmp, self.sa.state.solver.constExpr(4))
        
        return args

class PASCALFunctionInterceptor(FunctionInterceptor):
    args = ["revstack"]
    calleeclean = True
    
    def getArgs(self):
        args=[]
        
        for x in range(self.argc-1, -1, -1): #pascal reversed stack
            tmp=self.sa.state.solver.addExpr(self.sa.state.regs['ESP'], self.sa.state.solver.constExpr(4+(x*4))) #[ESP+4] == argN
            args.append(self.sa.getMemoryStateFromSolverState(tmp, 32))
        
        return args

class BORLANDFASTCALLFunctionInterceptor(FunctionInterceptor):
    args = ["EAX","ECX","EDX","revstack"]
    calleeclean = True
    
    def getArgs(self):
        args=[]
        if self.argc > 0:
            args.append(self.sa.state.regs["EAX"])
            if self.argc > 1:
                args.append(self.sa.state.regs["ECX"])
                if self.argc > 2:
                    args.append(self.sa.state.regs["EDX"])
                    if self.argc > 3:
                        for x in range(self.argc-3-1, -1, -1): #pascal reversed stack
                            tmp=self.sa.state.solver.addExpr(self.sa.state.regs['ESP'], self.sa.state.solver.constExpr(4+(x*4))) #[ESP+4] == argN
                            args.append(self.sa.getMemoryStateFromSolverState(tmp, 32))
        
        return args

class THISCALLFunctionInterceptor(FunctionInterceptor):
    args = ["ECX","stack"]
    calleeclean = True
    
    def getArgs(self):
        """
        arg0 == this
        arg1 == function arg0
        ...
        """
        
        args=[]
        args.append(self.sa.state.regs['ECX'])
        
        tmp=self.sa.state.solver.addExpr(self.sa.state.regs['ESP'], self.sa.state.solver.constExpr(4)) #[ESP+4] == arg0
        for x in range(0, self.argc):
            args.append(self.sa.getMemoryStateFromSolverState(tmp, 32))
            tmp = self.sa.state.solver.addExpr(tmp, self.sa.state.solver.constExpr(4))
        
        return args
