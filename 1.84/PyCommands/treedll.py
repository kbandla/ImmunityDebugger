#!/usr/bin/env python

"""
(c) Immunity, Inc. 2004-2008

U{Immunity Inc.<http://www.immunityinc.com>}

Tree Dll

"""

__VERSION__ = '1.0'

NAME = "treedll"
DESC="""Creates imported dll tree"""

import immlib
import immutils
import getopt

def usage(imm):
    imm.log("!%s" % NAME)
    imm.log("%s" % DESC)
    imm.log("-p    process name")
    imm.log("-l    max tree level")

class Node:
	def __init__(self, name):
		self.name = name
		self.imports = []
	def getName(self, name):
		return name
	def getImports(self):
		return self.imports
	def addImport(self, tl):
		self.imports.append( tl )

class DLLTree:
	def __init__(self, imm, entry = "", maxlevel = 3):
            self.imm = imm
	    if not entry:
		    self.entry = imm.getDebuggedName()
	    else:
		    self.entry = entry
	    self.node = None
	    self.maxlevel = maxlevel
            self.sym = None

	def Initalize(self):
	    self.sym = self.imm.getAllSymbols()
	
	def Get(self):
            if not self.sym:
		    self.Initalize()
	    self.tree = {}
	    self.checked = {}
	    self.node = self.buru(self.entry)
	    return self.node

        def Show(self):
	    if not self.node:
		    self.Get()
	
	    self.showNodeTree(self.node, 0, 0)

	def showNodeTree(self, node, num, level):
	    if level >= self.maxlevel:
		    return
	    self.imm.log(" " * num + node.name)
            self.checked[ node.name ] = 1 
	    for n in node.getImports():
		self.showNodeTree(n, num + 2, level+1)
	
	def buru(self, name):
	    if name in self.checked.keys():
		    return None
            tl = []
	    self.checked[name] = Node( name )
            try:
		tl = self.getAssociatedDLL(name)
            except Exception, msg:
                self.imm.log("Exception: %s" % str(msg))
             
	    for nn in tl:
		    if nn != name:
			node = self.buru( nn )
			if not node:
			    node = self.checked[nn]
			self.checked[name].addImport( node )
	    return self.checked[name]
	
	def getAssociatedDLL(self, name):
                if not self.sym:
		    self.Initalize()
		
		tl = {}
		if name not in self.sym:
		    raise Exception, "Entry not a dll found: %s" % name
		symbols = self.sym[name]
		for a in symbols.keys():
		   s = symbols[a]
		   #self.imm.log("%s | %s " % (s.type, s.name)) 
		   if s.type[:6] == "Import":
			sname = s.name.split(".",1)[0].lower() + ".dll"
			if sname not in tl.keys():
				tl[sname] = 1
		return tl.keys()

def main(args):
	imm=immlib.Debugger()
	try:
		opts, argo = getopt.getopt(args, "p:l:")
	except getopt.GetoptError:
		usage(imm)
		return "Wrong Arguments (Check usage on the Log Window)"
   
	processname = None 
	level = 3

	for o,a in opts:
		if o == '-p':
			processname = a
		elif o == '-l':
			level = int(a, 16)
    
	if processname is None:
        usage(imm)
        return "See log for usage info"

    d = DLLTree(imm, processname, level)
	d.Show()


	return "Check log window for results."
