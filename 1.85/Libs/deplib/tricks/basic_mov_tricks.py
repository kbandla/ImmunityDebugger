"""
- pop REG
- POP R1/POP R2/SUB|ADD R1,R2
- POP R1/SUB|ADD R1, CONTEXT
- MOV REG, CONST (check current context, it might already have that value)
"""

def init(instance):
    instance.register_operation("mov")
    instance.register_handler("mov", myhandler, pref=10)

def myhandler(finder, args):
    print "myhandler:",repr(args)
    return True

