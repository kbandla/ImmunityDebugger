#!/usr/bin/env python
"""
Immunity Debugger Command Line Client

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} Remote Command Line Client
"""

import socket
import sys

"""
NOTE: Most of this cmdclient comes from Bas's PDB client
"""

__VERSION__ = '1.0'


    
class clientCore():
    def __init__(self,ip,port):
	self.ip=ip
	self.port=port
	self.s=None
	
        return
    
    def writeLine(self, line):   
        sys.stdout.write(line)
        sys.stdout.flush()
        return
        
    def readLine(self): 
        line = sys.stdin.readline()
        sys.stdin.flush()
        return line
        
    def getCommandLine(self, prompt):
        self.writeLine(prompt) 
        try:
            line = self.readLine()
        except:
            line = None
        return line
    
    def listCommands(self):
	
        cmd  = "Available commands:\n\n"
	cmd +="Expressions"
	cmd +="==========="
	cmd +="\n"
	cmd +="= expression	Ditto"
	cmd +="WATCH expression	Add watch"
	cmd +="W expression	Ditto"
	cmd +="Disassembler"
	cmd +="============"
	cmd +="\n"
	cmd +="U expresion	Follow address in Disassembler"
	cmd +="ORIG	Go to actual EIP"
	cmd +="\n"
	cmd +="Dump and stack"
	cmd +="=============="
	cmd +="\n"
	cmd +="D expression	Follow address in dump"
	cmd +="DUMP expression	Ditto"
	cmd +="DA [expression]	Dump in assembler format"
	cmd +="DB [expression]	Dump in hex byte format"
	cmd +="DC [expression]	Dump as ASCII text"
	cmd +="DS [expression]	Dump as addresses (stack format)"
	cmd +="DU [expression]	Dump as UNICODE text"
	cmd +="DW [expression]	Dump in hex word format"
	cmd +="STK expression	Follow address in stack"
	cmd +="\n"
	cmd +=" Assembling"
	cmd +=" =========="
	cmd +="\n"
	cmd +="A expression [,command]	Assemble at address"
	cmd +="\n"
	cmd +="Labels and comments"
	cmd +="==================="
	cmd +="\n"
	cmd +="L expression, label	Assign symbolic label to address"
	cmd +="C expression, comment	Set comment at address"
	cmd +="\n"
	cmd +="Breakpoint commands"
	cmd +="==================="
	cmd +="\n"
	cmd +="BP expression [,condition]	Set INT3 breakpoint at address"
	cmd +="BPX label	Set breakpoint on each call to external 'label' within the current module"
	cmd +="BPD label	Delete breakpoint on each call"
	cmd +="BC expression	Delete breakpoint at address"
	cmd +="CLEAR expression	Delete breakpoint at address"
	cmd +="BR expression1 [,expression2]	Set memory breakpoint on access to range"
	cmd +="BW expression1 [,expression2]	Set memory breakpoint on write to range"
	cmd +="BMD	Remove memory breakpoint"
	cmd +="HR expression	Set 1-byte hardware breakpoint on access to address"
	cmd +="HW expression	Set 1-byte hardware breakpoint on write to address"
	cmd +="HE expression	Set hardware breakpoint on execute at address"
	cmd +="HD [expression]	Remove hardware breakpoint(s) at address"
	cmd +="\n"
	cmd +="Tracing commands"
	cmd +="================"
	cmd +="\n"
	cmd +="STOP	Pause execution"
	cmd +="PAUSE	Ditto"
	cmd +="RUN	Run program"
	cmd +="G [expression]	Run till address"
	cmd +="GE [expression]	Pass exception to handler and run till address"
	cmd +="S	Step into"
	cmd +="P	Step over"
	cmd +="TA [expression]	Trace in till address"
	cmd +="TO [expression]	Trace over till address"
	cmd +="TC condition	Trace in till condition"
	cmd +="TOC condition	Trace over till condition"
	cmd +="TR	Execute till return"
	cmd +="TU	Execute till user code"
	cmd +="\n"
	cmd +="Immunity Debugger windows"
	cmd +="========================="
	cmd +="\n"
	cmd +="LOG	View Log window"
	cmd +="MOD	View Executable modules"
	cmd +="MEM	View Memory window"
	cmd +="CPU	View CPU window"
	cmd +="KB	View Call Stack"
	cmd +="BRK	View Breakpoints"
	cmd +="INFO 	View Breakpoints"
	cmd +="OPT	Edit options"
	cmd +="\n"
	cmd +="Miscellaneous commands"
	cmd +="======================"
	cmd +="\n"
	cmd +="![pycmd] [arg1] [arg2] [argN]	Executes PyCommand"
	cmd +="EXIT	Closes this shell"
	cmd +="OPEN [filename]	Open executable file for debugging"
	cmd +="PYRUN python filename	Run python script"
	cmd +="RUNPY python filename	Run python script"
	cmd +="CLOSE	Close debugged program"
	cmd +="RST	Restart current program"
	cmd +="VCG address	Graph given address"
	cmd +="GRAPH address	Graph given address"
	cmd +="HELP	Show this help"
	cmd +="\n"
	cmd +="\n"
	cmd +="Commands are not case-sensitive, parameters in brackets are optional. "
	cmd +="Expressions may include constants, registers and memory references and "
	cmd +="support all standard arithmetical and boolean functions. "
	cmd +="By default, all constants are hexadecimal."
	cmd +="To mark constant as decimal, follow it with decimal point. Examples:"
	cmd +="    2+2 - calculate value of this expression;"
	cmd +="    AT [EAX+10] - disassemble at address that is the contents of memory doubleword at address EAX+0x10;"
	cmd +="    BP KERNEL32.GetProcAddress - set breakpoint on API function. Note that you can set breakpoint in system DLL only in NT-based operating systems;"
	cmd +="    BPX GetProcAddress - set breakpoint on every call to external function GetProcAddress in the currently selected module;"
	cmd +="    BP 412010,EAX==WM_CLOSE - set conditional breakpoint at address 0x412010. Program pauses when EAX is equal to WM_CLOSE."
	self.writeLine(cmd)
        return
    
    
    def exitCmdCli(self):
	self.writeLine("Exiting...\n")
	self.s.send("disconnect\n")
	self.s.close()
	sys.exit(1)
	
	
    def handleCommand(self, cmd):
	rcmd=cmd.replace("\n","")
	if rcmd == "help":
	    self.listCommands()
	elif rcmd == "quit" or rcmd == "exit":
	    self.exitCmdCli()
	else:
	    self.s.send(rcmd+"\n")
	    answer=self.s.recv(512)
	    if len(answer) > 0:
		self.writeLine(answer+"\n")
	    
	    
    
    def connectToImmdbg(self):
	self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
	    self.s.connect((self.ip,self.port))
	except:
	    self.writeLine("Could not connect...\n")
	    self.exitCmdCli()
	
	


def main():
    if len(sys.argv) < 3:
	print "Usage: %s ip port" % sys.argv[0]
	sys.exit(0)
    ip=sys.argv[1]
    port=int(sys.argv[2])
    client=clientCore(ip,port)
    client.connectToImmdbg()
    while 1:
        line = client.getCommandLine("ImmunityDebugger> ")
	if line == None:
            continue
	client.handleCommand(line)
	    	   
    return
     
     
     
     
if __name__=="__main__":
    main()