#/usr/bin/env python

import getopt
import xmlrpclib
import traceback
import struct
import debugger #needed on old ID for removeHook

from immlib import *

LICENSE="BSD 3-clause non-attribution" #yay!
copyright="(C) Immunity, Inc., jms@bughunter.ca"

"""

This script supports the SQLOLEDB method of executing queries and, when
combined with sql_listener.py will send you all the queries executed by a web
application. Server-side filtering (necessary to avoid sending thousands of
queries a second to you on a busy server) is stubbed in for later. We hooked
IIS rather than SQL Server because common practice is to have your SQL tier
un-routable, but the web tier is likely to have Internet access.

Somewhat later we'll have this integrate into SPIKE Proxy and other tools to
automate detection of blind-sql attacks/detection and sql injection in
general.

In order to use this script:

1. Run a few queries against your target server, this will start up two
dllhost.exe's

2. Load Immunity Debugger and attach to the second dllhost.exe (this can be
slightly tricky if the PID for the second one is lower than the first, but
eventually we'll automate it)

3. run !sqlhooker -s myhostip:myport. For example, I use !sqlhooker
192.168.1.1:8081, and then on my .1 machine I run "python sql_listener.py
8081".

Here's an example snippet of ASP script this would work against:
_start cut_
set conn = server.createObject("ADODB.Connection")
set rs = server.createObject("ADODB.Recordset")

query = "select count(*) from users where userName='" & userName & "' and userPass='" & password & "'"

conn.Open "Provider=SQLOLEDB; Data Source=(local); Initial Catalog=myDB; User Id=sa; Password="
rs.activeConnection = conn
rs.open query
_end cut_
We currently support:

WinXPPro Sp2, IIS 5.0 SQLServer 2000
Win2K3, IIS 6.0, SQLServer 2000
Win2K, IIS 5.0, SQLServer 2000
Win2K Old,IIS 5.0, SQLServer 2000

If anyone has requests for other database systems, they should email us, along
with the necessary information to get an application running, and we will
spend the time to find you hook spots. Or just submit a patch to
forum.immunityinc.com.


"""

class ole_hooker(LogBpHook):
    
    def __init__(self,hook_version,xmlhost=None,xmlport=0):
        
        LogBpHook.__init__(self)
        
        self.imm              = Debugger()
        self.hook_version     = hook_version
        self.xmlhost          = xmlhost
        self.xmlport          = int(xmlport)
        
    def run(self,regs):
        '''
        Called everytime the SQL hook is hit.
        '''
                
        self.imm.log("Hook version: %s" % self.hook_version)
        
        if self.hook_version == "winxp_pro_sp2" or self.hook_version == "win2k3":
            sql_addr = regs['EDI']
        
        if self.hook_version == "win2k":
            sql_addr = regs['ESI']
        
        if self.hook_version == "win2k_old":
            buffer_ptr = self.imm.readMemory(regs['ESP'] + 4, 4)
            buffer_ptr = struct.unpack("L", buffer_ptr)
            sql_addr = buffer_ptr[0]
            
        sql_query = self.imm.readWString(sql_addr)
        sql_query = sql_query.replace("\x00","")
                                
        self.imm.log("SQL Query: %s" % sql_query)
        
        using_xml_rpc = False
        
        if self.xmlport != 0:
            server = xmlrpclib.ServerProxy("http://%s:%d/"%(self.xmlhost,self.xmlport), allow_none=True)
            self.imm.log("Using server: %s:%d"%(self.xmlhost, self.xmlport))
            using_xml_rpc = True
        else: 
            server = None 
        
        if using_xml_rpc:
            #send our xml request to the remove side
            #if self.filter matches...(stub for now)
            try:
                result = server.sendsql(("sqlquery",[sql_query]))
            except:
                data=traceback.format_exc()
                self.imm.log("Failed to connect to remote server, sorry")
                self.imm.logLines("Error was: %s"%data)
                return
            
            #Now parse what we got back - a command and list of arguments
            command, arguments = result
            if command=="NEWFILTER":
                #stub
                self.filter=arguments[0]
            elif command=="UNHOOK":
                #stub
                self.imm.log("Unhook called")
            #etc
        return 
    
def usage(imm):       
    imm.log("!sqlhooker.py")
    imm.log("-u               (to uninstall hook)")
    imm.log("-s host:port     (Server to send XML-RPC data to)")

def main(args):
    
    imm = Debugger()
    
    xmlhost = None
    xmlport = 0
    
    sql_oledb = imm.getModule("sqloledb.dll")
    
    if not sql_oledb.isAnalysed():
        imm.analyseCode(sql_oledb.getCodebase())
    
    try:
        opts,argo = getopt.getopt(args, "ius:")
    except:
        return usage(imm)
    
    for o,a in opts:
        if o == "-u":
            if hasattr(imm, "removeHook"):
                imm.removeHook("query")
            elif hasattr(debugger, "remove_hook"):
                debugger.remove_hook("query")
            else:
                imm.log("Could not remove hook - no remove hook function found!")
            return "Removed hook on SQL function."
        if o == "-s":
            xmlhost,xmlport = a.split(":")
        
    
    # Various versions, we need to match on
    winxp_pro_sp2    =    "2000.085.1117.00 (xpsp_sp2_rtm."
    win2k3           =    "2000.086.3959.00 (srv03_sp2_rtm"
    win2k            =    "2000.081.9031.018"
    win2k_old        =    "2000.080.0194" 
    
    version = sql_oledb.getVersion()

    sql_base = sql_oledb.getBaseAddress()
    
    if version == winxp_pro_sp2:
        offset = 0xF6F5
        hook_version = "winxp_pro_sp2"
    
    if version == win2k3:
        offset = 0x6522
        hook_version = "win2k3"
    
    if version == win2k:
        offset = 0xFA2D
        hook_version = "win2k"
    
    if version == win2k_old:
        offset = 0x4034 
        hook_version = "win2k_old"
        
    bp_address = sql_base + offset
    
    # Set a hook
    hooker = ole_hooker(hook_version,xmlhost,xmlport)
    hooker.add("query",bp_address)
        
    return "SQL Hooks in Place. Ready for Test Cases."
