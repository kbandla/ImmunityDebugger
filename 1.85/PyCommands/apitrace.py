# apitrace PyCommand - (c)Immunity Inc.
# Justin Seitz <justin@immunityinc.com>
# TODO: 
# - dereference stack params if the function doesn't contain symbols

import getopt

from immlib import *

NAME = "apitrace"

def usage(imm):
    imm.log("!%s    Hooks all intermodular function calls" % (NAME))
    imm.log("       (excluding Rtl* by default). The -i and -e options")
    imm.log("       specify strings that if found in a function name")
    imm.log("       result in it being included or excluded from the")
    imm.log("       trace")
    imm.log("-i     Include pattern")
    imm.log("-e     Exclude pattern")
    imm.log(" ")
    imm.log("e.g. !apitrace -i msvcrt -e printf")
    imm.log("The above will hook all calls with msvcrt in the name")
    imm.log("excluding those with printf. So msvcrt.memset will be")
    imm.log("logged but not msvcrt._vsnwprintf")

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
        self.imm.log("Module that just got loaded: %s" % event.lpImageName)
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
                    self.imm.log("")
                    self.imm.log("Function Call -> %s" % i.getProcedure(), address = regs['EIP'])
            else:
                self.imm.log("%s" % i.getProcedure() )
        
def main(args):
    
    imm = Debugger()
    include_pattern = exclude_pattern = None

    try:
        opts, args = getopt.getopt(args, "i:e:")
    except getopt.GetoptError:
        usage(imm)
        return "Incorrect arguments (Check log window)"

    for o, a in opts:
        if o == "-i":
            include_pattern = a
        elif o == "-e":
            exclude_pattern = a
        else:
            usage(imm)
            return "Incorrect arguments (Check log window)"

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
        function_suffix = function_name.split(".")[1]

        # Skip any Rtl* calls, we are just splitting a string like kernel32.LoadLibraryA
        if function_suffix.startswith("Rtl"):
            continue
        
        if exclude_pattern is not None and \
            function_name.find(exclude_pattern) != -1:
            continue
        
        if include_pattern is not None and \
            function_name.find(include_pattern) == -1:
            continue

        hooker.add( function_name, call_list[call][0][2] )

        
        imm.log("From: 0x%08x -> To: 0x%08x (decoded: %s) " % \
            (int(call),int(call_list[call][0][2]),function_name))


    return "[*] All intermodular calls found and hooked."
