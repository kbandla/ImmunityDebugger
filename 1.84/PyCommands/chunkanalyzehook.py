#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}
"""

import immlib
import getopt
from libheap import *
from immlib import LogBpHook
import libdatatype

DESC = "Analize a Specific Chunk at a specific moment"

def usage(imm):
    imm.log("!chunkanalyzehook -a ADDRESS < exp >", focus=1)
    imm.log("  ADDRESS    of the place where you want to set a hook")
    imm.log("  < exp >    expression to calculate the chunk address")
    imm.log("ex: !chunkanalyzehook -a 0x1006868 EDI - 4")

FunctionsType = [ "+", "-", "*", "/", "&", "^"]

# Hook and Dump some Chunks based on the Expression
class HookAndInform(LogBpHook):
    Functions = { "+": lambda a,b: a+b,
                  "-": lambda a,b: a-b,
                  "*": lambda a,b: a*c,
	          "/": lambda a,b: a/c,
	          "&": lambda a,b: a&c,
	          "^": lambda a,b: a^c
			 }

    def __init__(self, exp, discover = False, nchunks = 3, heap = 0):
        LogBpHook.__init__(self)
        self.Expression = exp
	self.discover = discover
	self.nchunks = nchunks
	self.heap = heap


    def run(self, regs):
        imm = immlib.Debugger()
	    
        accumulator = 0
	second = 0
	func = '+'
	# Calculate the Chunk Address based on the Expression
	for value in self.Expression:
            if value in self.Functions.keys():
                func = value
            else:
                if type(value) == type(0):
                   second = value
                elif regs.has_key(value.upper()): 
                    second = regs[ value.upper() ]
                elif value[0]=='[' and value[-1] ==']' and regs.has_key(value[1:-1].upper()):
                    second = imm.readLong( regs[ value[1:-1].upper()] ) 
                else: 

			self.unHook()
		accumulator = self.Functions[func]( accumulator, second)
	imm.log("> Hit Hook 0x%08x, checking chunk: 0x%08x" % (self.address, accumulator), address = accumulator)
	imm.log("=" * 47)

	pheap = PHeap( imm, self.heap )
	plookaddr = 0
	if self.heap:
            plookaddr = pheap.Lookaddr
	hlook = None
        if plookaddr:
            hlook = PHeapLookaside( imm, plookaddr )
	dt = None
	if self.discover:
	    dt = libdatatype.DataTypes(imm)
        pheap = PHeap( imm )
	for chk in pheap.getChunks( accumulator, self.nchunks ):
            if chk.size < 0x7F and hlook:
		    l = hlook[ chk.size ]
                    if not l.isEmpty():
		        if chk.addr+8 in l.getList():
		            imm.log("- LOOKASIDE -")
            chk.printchunk(uselog = imm.log, dt = dt)
        imm.log("=-" * 0x23 + "=") 



def main(args):
    imm = immlib.Debugger()
    if not args:
       usage(imm)
       return "Wrong Arguments (Check usage on the Log Window)"
    try:
        opts, argo = getopt.getopt(args, "h:n:a:d")
    except getopt.GetoptError:
        return "Wrong Arguments (Check usage on the Log Window)"

    address = None
    expression = argo
    discover = False
    nchunks  = 3
    heap = 0

    for o,a in opts:
        if o == '-a':
	    try:		
                address = int( a, 16 )
            except ValueError:
                usage(imm)		    
                return "Wrong Address (%s) % " % a
	elif o == '-d':
            discover = True
	elif o == '-n':
            nchunks  = int( a, 16 )
	elif o == '-h':
            heap  = int( a, 16 )

    imm.log("Expression: %s" % argo)
    if not address and not expression:
        usage( imm )
        return "Wrong usage (Check usage on the Log Window)"	

    accumulator = 0
    func = '+'
    regs = {'EIP': 0L, 'ESP': 0L, 'EDI': 0L, 'EAX': 0L, 'EBP': 0L, 'EDX': 0L, 'EBX': 0L, 'ESI': 0L, 'ECX': 0L}
    # normalizing and checking the expression
    for ndx in range(0, len(expression) ):
        value = expression[ndx]
	if value not in FunctionsType:
	    if value.upper()  in regs.keys():
                expression[ndx] = value.upper()
            elif value[0]=='[' and value[-1] ==']' and regs.has_key(value[1:-1].upper()):
                expression[ndx] = value.upper()
            else:
	        try:
	           value = int(value, 16)
                   expression[ndx] = value		  
	        except ValueError:
                   imm.log("Wrong Argument: %s" % value)
	           return "Wrong Argument, Hook not setted"
    
    imm.log("Hooking on expression: '%s'" % str(expression) )

    hook = HookAndInform( expression, discover, nchunks = nchunks, heap = heap )
    hook.add("hook_inform_0x%08x" % address, address)    
    return "Hooked on 0x%08x" % address 
	     
	           
        
