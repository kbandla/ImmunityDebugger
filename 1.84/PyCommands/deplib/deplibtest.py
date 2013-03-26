from immlib import *
from deplib.deplib20 import *
import pprint
import sys
pp=pprint.PrettyPrinter()

a=deplibCompiler()
a.setLocals(sys.modules[__name__])
imm=Debugger()


f=DeplibFinder({"stackpage":4, "dbname":"gadgets.sq3", "modules":"notepad.exe"})
f.processCommands(a)
f.currentCommand={}
f.currentCommand["protectedcmd"]=False
exp=f.state.regs["EBX"]+f.state.regs["EBP"]
imm.log("%s"%f.moveExprToReg(exp))
for k,v in f.gadgets.iteritems():
    imm.log("%s:%08x"%(str(k),int(v)))

for k,v in f.rop.iteritems():
    imm.log("%s:%02x"%(str(k),int(v)))
