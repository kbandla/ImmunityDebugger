#!/usr/bin/env python

"""
Immunity Static Driver Analysis for Immunity Debugger

(c) Immunity, Inc. 2004-2006


U{Immunity Inc.<http://www.immunityinc.com>} Debugger Driver Library for python


"""

__VERSION__ = '1.0'

from immutils import *
from immlib   import *

import struct

class Driver:
    
    def __init__(self):
        
        # Globals
        self.imm                          = Debugger()
        self.IOCTLDispatchFunction        = None
        self.IOCTLDispatchFunctionAddress = 0x00000000
        self.IOCTLCodes                   = []
        self.IOCTLCodesLanding            = {}
        self.deviceNames                  = []
        self.module                       = self.imm.getModule( self.imm.getDebuggedName() )
        
        # Do some quick setup
        if not self.module.isAnalysed:
            self.imm.analyseCode( self.module.getCodebase() )
    

    def getIOCTLCodes( self ):
        """
        Useful function to root out IOCTL codes from a driver. 
        This is also a big part of automating ioctlizer.
        
        @rtype:   List
        @returns: List of all IOCTL codes that are supported by the driver.
        """
        if not self.IOCTLCodes:
                
            if self.IOCTLDispatchFunction is None:
                self.getIOCTLDispatch()
            
            bb_list = self.IOCTLDispatchFunction.getBasicBlocks()
            
            # Each IOCTL call has to do some setup first and then make a 
            # decision on the dwIoctlCode, so get the first basic block
            # start disassembling from the end backwards
            first_bb = bb_list[0]
            instruction_list = first_bb.getInstructions( self.imm )[::-1]
            
            term_jmp_found    = False
            first_ioctl_code  = None
            
            for instruction in instruction_list:
                
                inst_string = instruction.getResult()
    
                # We first confirm that we are terminated by a conditional
                # jump so that we can now look for a CMP/SUB with a constant
                # that will contain the IOCTL code
                if not term_jmp_found and instruction.isConditionalJmp():                
                    term_jmp_found = True
                    continue
                
                if "CMP" in inst_string or "SUB" in inst_string and term_jmp_found:
                    ioctl_code = instruction.getImmConst()
                    self.imm.log("First IOCTL code: 0x%08x" % int(ioctl_code))
                    
                    first_ioctl_code  = int(ioctl_code)
                    break
            
            
            # Now we put ourselves into a dissasembling frenzy
            # A CMP instruction means we don't modify the IOCTL code
            # A SUB/ADD instruction means we have to adjust the IOCTL code before storing it
            self.IOCTLCodes.append( first_ioctl_code )
            self.IOCTLCodesLanding[ first_ioctl_code ] = bb_list[0].getTrueEdge()
        
            base_register = instruction.getOperandRegister(0)
            
            # We aren't interested in the True edge, that's for the 
            # already discovered first_ioctl_code
            continue_search = True
            current_bb      = bb_list[0]
            
            # Just key a dict with the bb heads for quick access later
            basic_block_head_addresses = {}
            for bb in bb_list:
                basic_block_head_addresses[bb.getStart()] = bb
            
            modifier           = first_ioctl_code
            reg_modifier       = None
            reg_modifier_value = 0
            
            while continue_search:
                
                false_edge       = current_bb.getFalseEdge()
                if false_edge is None:
                    break
                
                current_bb       = basic_block_head_addresses[ false_edge ]
                instruction_list = current_bb.getInstructions( self.imm )
                
                # Now we have the false edge in the list let's
                # check for our IOCTL comparisons
                for instruction in instruction_list:
                    
                    # Something is being done TO the base_register
                    if base_register == instruction.getOperandRegister(0):
                        
                        # Ok now we know that our base register is being
                        # either compared or manipulated
                        inst_string = instruction.getResult()
                        
                        const       = instruction.getImmConst()
                        const_found = False
                        
                        # This means we have a valid constant being used
                        # otherwise we need to track down the register being used.
                        if "CMP" in inst_string:
                            self.IOCTLCodes.append( const )
                            self.IOCTLCodesLanding[ const ] = current_bb.getTrueEdge()
                            break
                        
                        if "SUB" in inst_string:

                            # We have tracked a modifier that's been assigned to 
                            # a register that's being subtracted from our IOCTL code        
                            if reg_modifier is not None:
                                
                                if instruction.getOperandRegister(1) == reg_modifier and instruction.getOperandRegister(0) == base_register:
                                    const       = reg_modifier_value
                                    const_found = True
                                    self.imm.log("Reg modifier check: 0x%08x" % reg_modifier_value)
                                    
                                # Check to make sure we aren't modifying the modifier :)
                                if instruction.getOperandRegister(1) == reg_modifier and instruction.getImmConst() != 0:
                                    reg_modifier_value = reg_modifier_value - instruction.getImmConst()
                                    const_found        = True
                                    self.imm.log("Reg modifier check 2")
                                    
                            if not const and not const_found:
                                # K now we gotta track down that pesky register
                                reg_modifier = instruction.getOperandRegister(1)
                            
                                # Now we disassemble backwards looking for a constant
                                rev_instruction_list = instruction_list[::-1]
                            
                                for search_instruction in instruction_list:
                                    mod_constant = search_instruction.getImmConst()
                                    
                                    if mod_constant:
                                        reg_modifier_value = mod_constant                                
                                        const              = mod_constant
                                        break
                                    
                            self.imm.log("Address: 0x%08x" % instruction.getAddress(), address = instruction.getAddress() )
                            
                            modifier = modifier - const
                            self.IOCTLCodes.append( modifier )
                            self.IOCTLCodesLanding[ modifier ] = current_bb.getTrueEdge()
                            break
                  
        # Now pretty print them out        
        for ioctl_code in self.IOCTLCodes:
            self.imm.log("IOCTL Code: 0x%08x" % ioctl_code)
        
        return self.IOCTLCodes
            
    def getDeviceNames( self ):
        """
        Attempts to discover all registered device symbolic links
        which are how usermode talks to the driver.
        
        @rtype:  List
        @return: List of all possible devices names.
        """
        
        string_list      = self.imm.getReferencedStrings( self.module.getCodebase() )
                
        for entry in string_list:
            if "\\Device\\" in entry[2]:
                self.imm.log("Possible match at address: 0x%08x" % entry[0], address = entry[0] )
                self.deviceNames.append( entry[2].split("\"")[1] )
                

        self.imm.log("Possible device names: %s" % self.deviceNames)
        
        return self.deviceNames

    
    def getIOCTLDispatch( self ):
        """
        Locates the primary dispatch function for handling IOCTLs from
        userland.
        
        @rtype: Function object
        @return: Function object.
        """
        
        # The IOCTL dispatch is always located at MOV DWORD PTR [R32+0x70], CONST
        search_pattern = "MOV DWORD PTR [R32+70],CONST"
        
        dispatch_address = self.imm.searchCommandsOnModule( self.module.getCodebase(), search_pattern )
        
        # We have to weed out some possible bad matches
        for address in dispatch_address:
            
            instruction = self.imm.disasm( address[0] )
            
            if "MOV DWORD PTR" in instruction.getResult():
                if "+70" in instruction.getResult():
                    self.IOCTLDispatchFunctionAddress = instruction.getImmConst()
                    self.IOCTLDispatchFunction        = self.imm.getFunction( self.IOCTLDispatchFunctionAddress )
                    break
        
        if not self.IOCTLDispatchFunctionAddress and not self.IOCTLDispatchFunction:
            # If that first loop fails, then we start walking the driver
            # until we freakin' find it, slow but accurate
            function_list = self.imm.getAllFunctions( self.module.getCodebase() )
            
            for function in function_list:
                
                bb_list = self.imm.getFunction( function ).getBasicBlocks()
                
                for bb in bb_list:
                    instruction_list = bb.getInstructions( self.imm )
                    
                    for instruction in instruction_list:
                        
                        if "MOV DWORD PTR" in instruction.getResult():
                            if "+70" in instruction.getResult():
                                self.IOCTLDispatchFunctionAddress = instruction.getImmConst()
                                self.IOCTLDispatchFunction        = self.imm.getFunction( self.IOCTLDispatchFunctionAddress )
                                break
            
        if self.IOCTLDispatchFunction:                   
            self.imm.log("Dispatch address: 0x%08x" % self.IOCTLDispatchFunctionAddress, address = self.IOCTLDispatchFunctionAddress )        
        else:
            self.imm.log("Couldn't find an IOCTL dispatch routine. Driver may not support usermode calls in this manner.")
           
        
        return self.IOCTLDispatchFunction
    
    def printDriverReport( self ):
        """
        This simply runs all of the functions and outputs as much information as it
        can gather about the driver, spits it all out into the log window and 
        drops a text file called driver_name_report.txt with all of the information.
        """
        # TODO: make this do what i said it's gonna do
        self.getIOCTLDispatch()
        
        if self.IOCTLDispatchFunctionAddress:
            self.getIOCTLCodes()
        
        self.getDeviceNames()

        fd = open("%s.txt" % self.imm.getDebuggedName(), "w")
        
        self.imm.log("=" * 512)
        fd.write("=" * 512)
        fd.write("\n")
        
        msg = "Driver Report for: %s (Version: %s)" % ( self.imm.getDebuggedName(), self.module.getVersion() )
        self.imm.log("%s" % msg)
        self.imm.log("")
        fd.write( msg + "\n\n")
        
        msg = "Discovered Device Names:"
        self.imm.log("%s" % msg)
        fd.write( msg + "\n")
        
        for device_name in self.deviceNames:
            self.imm.log( "%s" % device_name)
            fd.write( device_name + "\n" )
        self.imm.log("")
        fd.write("\n")
        
        if self.IOCTLDispatchFunctionAddress:
            msg = "IOCTL Dispatch located at: 0x%08x (+%08x)" % ( self.IOCTLDispatchFunctionAddress, (self.IOCTLDispatchFunctionAddress - self.module.getBase() ) )
            self.imm.log("%s" % msg, address = self.IOCTLDispatchFunctionAddress)
            self.imm.log("")
            fd.write( msg + "\n\n")
            
            msg = "IOCTL Codes:"
            self.imm.log("%s" % msg)
            self.imm.log("")
            fd.write( msg + "\n\n")
            
            for ioctl_code in self.IOCTLCodes:
                
                msg = "0x%08x" % ioctl_code
                self.imm.log("%s" % msg)
                fd.write( msg + "\n")
            
            self.imm.log("")
            fd.write("\n")
            
            msg = "IOCTL Codes Landing Basic Blocks ( IOCTL CODE => Landing Address ( Relative Offset ) ):"
            self.imm.log("%s" % msg)
            self.imm.log("")
            fd.write( msg + "\n\n")
            
            for ioctl_code in self.IOCTLCodes:
                
                msg = "0x%08x => 0x%08x (+%08x)" % ( ioctl_code, self.IOCTLCodesLanding[ ioctl_code ], ( self.IOCTLCodesLanding[ ioctl_code ] - self.module.getBase() ) )
                self.imm.log("%s" % msg, address = self.IOCTLCodesLanding[ ioctl_code ] )
                fd.write( msg + "\n")
            
        self.imm.log("")
        fd.write("\n")
        
        
                                                                
        
        fd.close()
        return 
