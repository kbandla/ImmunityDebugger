#!/usr/bin/env python
"""

nohooks

"""

__VERSION__ = '0.1'

DESC="""Clean all hooks from memory"""

import immlib
    
def main(args):
    imm = immlib.Debugger()
    for hook in imm.listHooks():
        imm.removeHook(hook)
        imm.log("Removed \"%s\" hook from memory" % str(hook))
    return "Hooks removed"
