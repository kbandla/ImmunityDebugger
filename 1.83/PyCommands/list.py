#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}

List all pycommands with its descriptions in log window

"""

DESC="""List PyCommands"""

import immlib
import os

CMD_DIR = "./PyCommands"

def do_dir_list(imm, path):
    dir_list = os.listdir(path)
    for name in dir_list:
        if name[-3:] == ".py":
            imm.log("* %s" % name)

def main(args):
    imm=immlib.Debugger()

    dir_list = os.listdir(CMD_DIR)
    imm.log("List of available PyCommands")

    for name in dir_list:
        path = os.path.join(CMD_DIR, name)
        if os.path.isdir(path):
            do_dir_list(imm, path)
        elif name[-3:] == ".py":
            imm.log("* %s" % name) 

    imm.log("",focus=1)
    return "See log window for results"
    
