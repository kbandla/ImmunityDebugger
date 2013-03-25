import immutils
from immlib import *
import getopt

# Hook names, no need for an explanation
HOOK_NAME = "vct_hook"

# Symbol names of the functions we want to hook
HOOK_SYMS = ["VariantChangeTypeEx"]

# Module name, just to know where we are
HOOK_MODULE = "OLEAUT32"

class VCTHook(LogBpHook):
    """
    VariantChangeType Hook
    
    This hook is used to check if the arguments of VariantChangeType are pointers
    to the same object. There might be vulnerabilities in code that call this function
    in such a manner.
    """
    def __init__(self):
        LogBpHook.__init__(self)
        self.dbg = Debugger()
        self.count = 0

    def run(self, regs):
        pvargDest = self.dbg.readLong(regs['ESP'] + 0x4)
        pvarSrc = self.dbg.readLong(regs['ESP'] + 0x8)
        third = self.dbg.readLong(regs['ESP'] + 0xc)

        if pvargDest == pvarSrc:
            self.dbg.log("-"*80)
            call_stack = self.dbg.callStack()
            for frame in call_stack:
                self.dbg.log("Address = %08x | Stack = %08x | Procedure %s | Frame %08x | Called from %08x" \
                    %(frame.address, frame.stack, frame.procedure, frame.frame, frame.calledfrom), address=frame.calledfrom)

def usage(dbg):
    dbg.log("!VCTHook.py")
    dbg.log("-u               (to uninstall hook)")

def main(args):
    """
    """
    dbg = Debugger()
    
    mod = dbg.getModule(HOOK_MODULE)
    
    try:
        opts, argo = getopt.getopt(args, "ulc:", ["remove", "list", "count"])
    except getopt.GetoptError, err:
        usage(dbg)
        return str(err)
        
    for o,a in opts:
        if o == "-u":
            # TODO check if the hook exists
            dbg.removeHook(HOOK_NAME)
            return "Removed hook on %s." %(HOOK_NAME)
        elif o == "-l":
            hooks = dbg.listHooks()
            for hook in hooks:
                dbg.log(hook)
            return "OK"
        elif o == "-c":
            count = int(a)
            
    hooker = VCTHook()
    
    # Set hooks
    for sym_name in HOOK_SYMS:
        full_sym_name = HOOK_MODULE + "." + sym_name
        bp_address = dbg.getAddress(full_sym_name)
        dbg.log("Adding hook to %s on address %08x" %(full_sym_name, bp_address))
        hooker.add(HOOK_NAME, bp_address)
        
    return "Hooks are in Place!"

if __name__ == "__main__":
    main()

