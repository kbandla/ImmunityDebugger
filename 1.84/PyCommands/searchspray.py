# -*- coding: utf-8 -*-
from immlib import *
import getopt

def main(args):
    """
    Script to search all occurences of a string in memory and
    display them on a table. Useful (for me) to visualize heap
    layout created by heap spray.

    !searchspray -h fe ca fe ca 11 11 11 11
    !searchspray -s I am evil homer
    """
    imm = Debugger()

    try:
        opts, argo = getopt.getopt(args, "s:h:", ["string", "hex"])
    except getopt.GetoptError, err:
        usage(dbg)
        return str(err)

    opt = " ".join(args[1:]).strip('"')

    if args[0] == "-s":
        string = opt
    elif args[0] == "-h":
        string = "".join(["%c" % int(i, 16) for i in opt.split()])

    log = imm.createTable("Heap Spray", ["#", "Adddress",  "What?"])
    i = 0
    for a in imm.search(string):
        i += 1
        log.add(a, [str(i), str(hex(a)), " ".join(["%x" %ord(j) for j in string])])

    return "Logging to Heap Spray Window"
