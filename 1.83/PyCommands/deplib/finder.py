"""
Two main functions are defined in the GadgetFinder class: searchByHashes and searchByProperties and 
both return an iterator over the results from the database. Each result is a 3-tuple: module_id, module_offset, gadget_complexity.

Hash searching is very fast and it provides EXACT results. You model what you need by changing an empty state machine instance.

The state machine provides a set of registers, flags and memory variables that you can use to interact between them almost as natural python variables using PrettySolver notation.

So, if you need a stack pivot for EAX you could try something like:
sm.regs["ESP"]=sm.regs["EAX"]              #Emulate something like MOV ESP,EAX or XCHG EAX,ESP
sm.EIP = sm.readMemory(sm.regs["ESP"], 4)  #Emulate a RETN
sm.regs["ESP"]+=4                          #This would be for a clean RETN, other possibilities are +8 = RETN 4, etc etc. 

Remember that this type of search is EXACT, so it will look up exactly what you model.

If you need to assign a constant to a register, use this:
sm.regs["EBX"]=Expression(0x12345678)

Results are logged in the ID Log window.

The other search method (by properties) is heuristical and works by providing hints of what you need from the gadget.
This hints are modeled by telling DEPLIB what registers affect what other registers.
ex: in ADD EAX, EBX
EAX is being modified by EBX: props["EAX"]="EBX"
MOV ESI, 12345678
ESI is modified by a CONST: props["ESI"]="CONST"

and you can mix registers providing a tuple instead of a string:
ADD EAX, EBX
SUB EAX, EDX
EAX is modified by EBX AND EDX: props["EAX"]=("EBX","EDX")

Also you can model that some register is modified by memory indexed by some register:
OR EAX, [EDX]
EAX is modified by memory pointed by EDX: memProps["EAX"]="EDX"

Besides registers and CONST you can use the special keyword "FLAGS", meaning that the value of some register is tainted by some flag:
SBB EAX, EDX
regs["EAX"]=("EDX","FLAGS")


Finally, you can model that you need some processor flag to be modified or to be untouched by the gadget.
flagProps["C"]=True  #carry flag must be modified (either to become True or False, but it must modify CF)
flagProps["D"]=False #direction flag must NOT be modified by the gadget

"""

from deplib.libfinder import GadgetFinder
from x86smt.prettysolver import *
from x86smt.sequenceanalyzer import StateMachine
from immlib import *


def main(args):
    regProps={}
    memProps={}
    flagProps={}
    imm=Debugger()
    sm=StateMachine(solver=PrettySolver())
    
    #define the module/s to use in the search and all the database information here
    gf=GadgetFinder(imm, "explorer.exe")
    #gf._debug=True

    ##### DEFINE YOUR SEARCHING CONSTRAINS HERE #######

    #search for a SUB ESP, <range>
    for x in xrange(0x100,0x200):
        sm.push() #push SM state before modifing it so we can go back to the initial empty state in the next iteration
        sm.regs["ESP"]-=x
        
        results=gf.searchByHashes(sm)
        if results:
            for info in results:
                imm.log("module_id=%d, module_base=0x%x, offset=0x%x, complexity=%d"%(info[0], gf.bases[info[0]], info[1], info[2]), gf.bases[info[0]]+info[1])
        sm.pop() #go back to the initial empty state

    imm.log("########################################################################")
    
    #search for EAX = 0
    sm.regs["EAX"] = Expression(0)
    result=gf.searchByHashes(sm)
    if result:
        for info in result:
            imm.log("module_id=%d, module_base=0x%x, offset=0x%x, complexity=%d"%(info[0], gf.bases[info[0]], info[1], info[2]), gf.bases[info[0]]+info[1])
    
    imm.log("########################################################################")
    
    #typical stack pivot to EAX
    regProps["ESP"]="EAX"
    memProps["EIP"]="EAX"
    
    results = gf.searchByProperties(regProps, memProps, flagProps)
    if results:
        for info in results:
            imm.log("module_id=%d, module_base=0x%x, offset=0x%x, complexity=%d"%(info[0], gf.bases[info[0]], info[1], info[2]), gf.bases[info[0]]+info[1])
    else:
        imm.log("Nothing found")
