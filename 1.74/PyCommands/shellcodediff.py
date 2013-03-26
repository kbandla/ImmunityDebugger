#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2008


U{Immunity Inc.<http://www.immunityinc.com>}

Shellcode diff

"""

DESC="""Check for badchars"""

from immlib import *
import sys

sys.path.append(".")
sys.path.append("../PyCommands")

NAME = "shellcodediff"
USAGE = "address"

def main(args):
    imm = Debugger()
    
    if len(args) != 1:
        imm.log("Usage: !" + NAME + " " + USAGE)
	return "See log window for usage info"

    address  = 0
    length   = 0
    bad_byte_offset = 0
    mangled  = False
    
    address = int(args[0],16)

    fd = open("shellcode.txt","r")
    canvas_byte_list = fd.readlines()
    fd.close()

    canvas_shellcode = ""
    # Just pretty this up
    for i in canvas_byte_list:
        canvas_shellcode += i.rstrip("\x0a")
    length = len(canvas_shellcode) / 2

    id_shellcode = imm.readMemory( address, length )
    id_shellcode = id_shellcode.encode("HEX")
    imm.log("Address: 0x%08x" % address)
    imm.log("SC Len : %d" % length)

    imm.log("CANVAS Shellcode: %s" % canvas_shellcode[:512])
    imm.log("ID Shellcode: %s" % id_shellcode[:512])

    count = 0
    
    # We use the CANVAS shellcode length here again cause
    # presumably its not mangled
    while count <= (length*2):

        if id_shellcode[count] != canvas_shellcode[count]:

            imm.log("Missed at byte: %d" % count)
            bad_byte_offset = count
            mangled = True            
            break

        count += 1

    if mangled:
        imm.log(" ")
        imm.log("Bad byte is centered in output with three leading and three trailing bytes.")
        imm.log(" ")
        imm.log("Bad byte at offset: %d" % bad_byte_offset)
        imm.log("Bad byte value from attacker: %s" % canvas_shellcode[bad_byte_offset:bad_byte_offset+2])
        imm.log("====================\n\n")

        imm.log("CANVAS: %s %s %s" % (canvas_shellcode[bad_byte_offset-6:bad_byte_offset],canvas_shellcode[bad_byte_offset:bad_byte_offset+2],canvas_shellcode[bad_byte_offset+2:bad_byte_offset+6]))
        imm.log("ID    : %s %s %s" % (id_shellcode[bad_byte_offset-6:bad_byte_offset], id_shellcode[bad_byte_offset:bad_byte_offset+2],id_shellcode[bad_byte_offset+2:bad_byte_offset+6]))
        
        imm.log("\n\n====================")

        

    return "Shellcode diff output to log window."
