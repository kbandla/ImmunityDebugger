import os
import sys
import shutil
from x86smt.sequenceanalyzer import MyDebugger
from deplib.libgadgets import GadgetsDB
import time
import getopt
from immlib import *
from datetime import timedelta

def usage(imm):
    imm.log("!gadgets_db")
    imm.log("  -t sqlite3|mysql = Type of DB (sqlite3)")
    imm.log("  -n dbname        = DB name ('gadgets.sq3' if sqlite3 or 'gadgets' if mysql)")
    imm.log("  -h host          = host for the DB connection (127.0.0.1)")
    imm.log("  -u username      = username for the DB connection")
    imm.log("  -p password      = password for the DB connection")
    imm.log("  -m module        = Module to analyze and store (you can put multiple -m)")
    imm.log("  -c max           = How many gadget you want to analyze (All)")
    imm.log("  -f               = Force module re-analysis")
    imm.log("  -a               = Analyze ALL modules")
    imm.log("  -b               = DO NOT backup sqlite DB")
    imm.log("  -d               = Activate debugging")
    imm.log("  -l               = Log everything in a file")
    imm.log("  -i               = List modules present in the DB and some stats")
    imm.log("")
    imm.log("multiple -m options are accepted")

def main( args ):
    imm = Debugger()
    
    try:
        opts, argo = getopt.getopt(args, "t:n:h:u:p:m:c:adbfli")
    except getopt.GetoptError, reason:
        imm.log("[!] Exception when parsing arguments: %s" % reason)
        usage(imm)
        return "Error parsing arguments. See log for details"

    dbtype = dbname = host = username = passwd = maxgadgets = None
    allmodules = debug = nobackup = force = logfile = listmods = False
    modules=[]
    for o, a in opts:
        if o == "-t":
            dbtype = a
        elif o == "-n":
            dbname = a
        elif o == "-u":
            username = a
        elif o == "-p":
            passwd = a
        elif o == "-m":
            modules.append(a)
        elif o == "-c":
            maxgadgets = int(a)
        elif o == "-a":
            allmodules=True
        elif o == "-d":
            debug=True
        elif o == "-b":
            nobackup=True
        elif o == "-f":
            force=True
        elif o == "-l":
            logfile=True
        elif o == "-i":
            listmods=True
        elif o == "-h":
            host = a
        else:
            usage(imm)
            return "Unknown option"
    
    if not modules and not allmodules and not listmods:
        usage(imm)
        return "you must select a module to analyze and store"

    if logfile:
        gdbimm = MyDebugger(template="gadgets_db-log-")
    else:
        gdbimm = imm
    
    gdb = GadgetsDB(gdbimm, dbtype, dbname, host, username, passwd)
    gdb.debug=debug
    gdb.force_analysis=force
    gdb.max_gadgets=maxgadgets
    
    if not gdb.db_connection:
        imm.log("[!] Could not connect to db, exiting...")
        return "Failed to connect to DB"
    
    if dbtype == "sqlite3" and not nobackup and not listmods:
        imm.log("[*] Database backup: %s.bak" % gdb.database_file)
        shutil.copyfile(gdb.database_file, "%s.bak" % gdb.database_file)
    
    if listmods:
        gdb.list_modules()
    elif allmodules:
        gdb.all_module_scan()
    else:
        for modname in modules:
            module = imm.findModuleByName(modname)
            if not module:
                imm.log("[!] Module %s not found"%modname)
                continue
        
            gdb.add_module_entry(module)
    
    gdb.db_connection.close()
    return "Finished"
