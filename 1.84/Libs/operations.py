#!/usr/bin/env python

"""
(c) Immunity, Inc.

This is some code that will be sort of ugly by design.  Its purpose is to hide
the guts of Immunity Debugger from the rest of DEPLib and make the DEPLib code
more readable.
"""

"""Status:
For now, we only have here methods necessary to get the register tuples out of
sequenceanalyzer.py.  Other 'ugly' things we should get rid of:
multi-layer tuples (e.g., op.operand[0][1])
memory state tuples
remove need for fixOP2()
op.dump?
"""

from immlib import *

class operation(opCode):
	def __init__(self,op):
		self.__dict__ = op.__dict__.copy() 
		self.imm = op.imm
		
	def constantOperand(self, value, size=4):
		"""Returns an operand with the specified constant value.  
		Size is 4 bytes (32 bits) unless otherwise specified.
		"""
		return (DEC_CONST,size,(0,0,0,0,0,0,0,0), value)
	
	def emptyOperand(self):
		return (0,0,(0,0,0,0,0,0,0,0), 0)
	
	def memoryOperand(self, reg, offset=0):
		"""Returns an operand that accesses memory at a register + offset
		e.g., push [ebx+4]
		"""
		for key in RegisterName:
			if RegisterName[key] == reg:
				regtuple = key
				break
		return (4,4,regtuple,offset)
		
	def registerOperand(self, reg):
		"""Returns an operand that represents the specified register.
		"""
		for key in RegisterName:
			if RegisterName[key] == reg:
				regtuple = key
				break
		return (0x24,4,regtuple,0)
	
	def op1Type(self):
		return self.operand[0][0]
	def op2Type(self):
		return self.operand[1][0]
	def op3Type(self):
		return self.operand[2][0]
	def op1Size(self):
		return self.operand[0][1]
	def op2Size(self):
		return self.operand[1][1]
	def op3Size(self):
		return self.operand[2][1]
	def op1Register(self):
		return self.operand[0][2]
	def op2Register(self):
		return self.operand[1][2]
	def op3Register(self):
		return self.operand[2][2]
	def op1Constant(self):
		return self.operand[0][3]
	def op2Constant(self):
		return self.operand[1][3]
	def op3Constant(self):
		return self.operand[2][3]
	
	def removeLockPrefix(self):
		return self.getDisasm().upper().replace("LOCK ","").split(' ')[0]
		
	def usesForbiddenMemory(self):
		"""Returns True if an operation would write memory that is not writable
		or read memory that is not readable.
		"""
		#op1 on BT R,BTC RW, BTR RW, BTS RW, CMP/TEST R, CMPS R, LODS R, CMPXCHG RW, CMPXCHG8B RW, MUL R, IMUL R, DIV R, IDIV R, XADD RW, JMP R, CALL R
		#op2 on XADD RW
		cmd = self.removeLockPrefix()
		for x in range(0,3):
			if self.operand[x][0] & DECR_ISREG == 0 and self.operand[x][0] & DEC_CONST == 0 and \
			   self.operand[x][2] == (0,0,0,0,0,0,0,0) and self.operand[x][0] != 0:
				
				if "FS:" in self.result:
					fsfix = self.imm.getCurrentTEBAddress()
				else:
					fsfix = 0
				
				if x == 0:
					if   cmd in ["BT","CMP","TEST","CMPS","LODS","MUL","IMUL","DIV","IDIV","JMP","CALL","PUSH"]:
						if not self.imm.validateAddress(self.operand[x][3]+fsfix, "R"):
							return True
					elif cmd in ["CMPXCHG","CMPXCHG8B","BTC","BTR","BTS","XADD"]:
						if self.imm.validateAddress(self.operand[x][3]+fsfix, "RW"):
							return True
					elif not self.imm.validateAddress(self.operand[x][3]+fsfix, "W"):
						return True
				else:
					if cmd == "XADD":
						if not self.imm.validateAddress(self.operand[x][3]+fsfix, "RW"):
							return True
					elif not self.imm.validateAddress(self.operand[x][3]+fsfix, "R"):
						return True
		return False

	def validateInstruction(self):
		"""
		Check if the instruction is valid under a x86 userland windows process.
		
		"""
		
		if "Illegal" in self.comment:
			return False

		completeText = self.getDisasm().upper()
		
		#we dont really care about the LOCK prefix
		command = self.removeLockPrefix()
		
		if len(command) == 0 or "???" in command or self.getSize() == 0:
			return False
		
		#Blacklist any operation that use/change segment registers
		if self.op1Type() == DECR_SEG or self.op2Type() == DECR_SEG or self.op3Type() == DECR_SEG:
			return False

		#FAR operations are not supported
		if " FAR " in completeText:
			return False
		
		if "Unknown command" in self.comment or \
		   "I/O" in self.comment or \
		   "Far return" in self.comment or \
		   "Privileged command" in self.comment or \
		   "Modification of segment register" in self.comment:
			return False
		
		#blacklist some unknown segments operations
		if "SEG" in completeText:
			return False
		
		#invalidate forbidden memory addresses
		if self.usesForbiddenMemory():
			return False
		
		return True
