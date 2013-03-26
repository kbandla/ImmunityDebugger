# apitrace PyCommand - (c)Immunity Inc.
# Justin Seitz <justin@immunityinc.com>
# TODO: 
# - dereference stack params if the function doesn't contain symbols

from immlib import *

class ExportHooks(LoadDLLHook):
    
    def __init__(self):
        LoadDLLHook.__init__(self)
        self.imm    = Debugger()
        self.hooker = InterCallHook()
    
    def run(self, regs):
        
        # We gotta new DLL loaded, time to find all it's functions
        # and set breakpoints on them, hopefully to bypass the pain
        # of having to rebuild IATs.
        event = self.imm.getEvent()
        self.imm.Log("Module that just got loaded: %s" % event.lpImageName)
        #module = self.imm.getModule( event.lpImageName )
        
        # Force analysis
        self.imm.analyseCode( module.getCodebase() )
        
        # Now walk all the functions and set breakpoints on the functions
        # that we can resolve correctly
        function_list = self.imm.getAllFunctions( module.getCodebase() )
        
        for i in function_list:
            
            function = self.imm.getFunction( i )
            function_name = self.imm.decodeAddress( i )
            
            # Now we add all of our breakpoints to the main hook
            self.hooker.add( function_name, i )

            
class InterCallHook(LogBpHook):
    
    def __init__(self):
        LogBpHook.__init__(self)
        self.imm = Debugger()
        
    def run(self, regs):
        
        # We have hit the function head, now we decode
        # the function and all of its parameters, quite handy
        call_stack = self.imm.callStack()
        
        
        # Now we just do some funky workarounds to make sure
        # we are decoding the information correctly
        main_call = False
        
        for i in call_stack:
            
            if i.getProcedure().startswith(" ") == False:
                if main_call == True:
                    break
                else:
                    main_call == True
                    self.imm.Log("")
                    self.imm.Log("Function Call -> %s" % i.getProcedure(), address = regs['EIP'])
            else:
                self.imm.Log("%s" % i.getProcedure() )
        
def main(args):
    
    imm = Debugger()
    
    # Find all intermodular commands in the executable
    # and set a logging BP hook on them. Ignore all calls
    # to Rtl* as they need to be instrumented with fast hooks
    module = imm.getModule( imm.getDebuggedName() )

    # We use a LoadDLLHook so that if libraries get added
    # we automagically add the new functions to the global hook
    loaddll_hook = ExportHooks()
    loaddll_hook.add("Generic DLL handler.")
    
    hooker = InterCallHook()
    
    if not module.isAnalysed():
        imm.analyseCode( module.getCodebase() )
    
    call_list = imm.getInterCalls( module.getCodebase() )
    
    for call in call_list.keys():
                
        function_name = imm.decodeAddress( int(call_list[call][0][2]) )
        
        # Skip any Rtl* calls, we are just splitting a string like kernel32.LoadLibraryA
        if function_name.split(".")[1].startswith("Rtl"):
            continue
        
        hooker.add( function_name, call_list[call][0][2] )

        
        imm.Log("From: 0x%08x -> To: 0x%08x (decoded: %s) " % (int(call),int(call_list[call][0][2]),function_name))


    return "[*] All intermodular calls found and hooked."