"""funsniff"""

DESC="""funsniff """

import immlib
import immutils
import libdatatype

def usage(imm):
    imm.log("!finddatatype   ")
    imm.log("!finddatatype  ADDRESS SIZE")
    return "Usage: !finddatatype  ADDRESS SIZE"

def main(args):
    imm          = immlib.Debugger()
    if not args:
        return usage( imm )
    if len( args ) != 2:
        return usage( imm )
        
    addr = int(args[0], 16)
    size = int(args[1], 16)
    
    dt = libdatatype.DataTypes(imm)
    mem = imm.readMemory( addr, size )
    if not mem:
        return "Error: Couldn't read anything at address: 0x%08x" % addr
    
    ret = dt.Discover( mem, addr, what = 'all' )
    imm.log( "Found: %d data types" % len(ret) )

    for obj in ret:
        t = "obj: %d" % obj.size
        if obj.data:
            msg = obj.Print()
            imm.log( "obj: %s: %s %d" % (obj.name, msg, obj.getSize() ), address = obj.address)
            
    return "Found: %d data types" % len(ret)