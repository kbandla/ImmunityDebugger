import immlib, immutils

DESC = "Looks for mapped address that can be 'transformed' into opcodes"

def str2int24_swapped( value ):
    return istr2int( value + "\x00" ) 

def usage(imm):
    imm.log("!duality  Looks for mapped address that can be 'transformed' into opcodes")
    imm.log("!duality  <asm code>")
    

def main(args):
    imm = immlib.Debugger()
    found  = 0
    searchf = {1:ord, 2: immutils.str2int16_swapped,\
               3:str2int24_swapped}
    searchm = {1:0xff, 2:0xffff, 3: 0xffffff}
    
    code =  imm.assemble( " ".join(args) )
    mask = len(code)
    currentmask = searchm[mask] 

    try:
        what = searchf[ mask ]( code )
    except KeyError:
        return "Error, Code too big"
    
    imm.log("What: 0x%08x -> %s" % (what, " ".join(args)) )
    imm.getMemoryPages()

    for a in imm.MemoryPages.keys():

        mem = imm.MemoryPages[a]
        size  = mem.getSize()
        start = mem.getBaseAddress()
        end   = start + size
        
        ouraddr = ( start & ~currentmask) | what

        if ouraddr > start and ouraddr < end:
                imm.log("Found: 0x%08x %s" % (ouraddr, mem.getSection()), address = ouraddr)
                found+=1
        else:
            ouraddr+= currentmask+1
            if ouraddr > start and ouraddr < end:                
                    imm.log("Found: 0x%08x (%s)" % ( ouraddr, mem.getSection() ), address = ouraddr)
                    found+=1
    return "Addresses founded: %d (Check the Log Window)" % found