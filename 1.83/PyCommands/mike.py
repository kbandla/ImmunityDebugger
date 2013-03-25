import getopt
import struct
import time
import sys
import threading

from immutils        import * 
from immlib          import *
from libstackanalyze import *
from graphclass      import *
from immvcglib       import *
from socket          import *

DESC="""Attempts to automate tracing the lifecycle of a packet's contents."""

#############################################################################
'''
Some defines for re-use.
'''
PACKET_TYPE_SEND        =    "Send "
PACKET_TYPE_RECV        =    "Recv "
PACKET_PROTOCOL_UDP     =    "(UDP)"
PACKET_PROTOCOL_TCP     =    "(TCP)"

#############################################################################
class packet_analyzer(BpHook):
    
    #########################################################################
    def __init__(self, address, hook_type):
        
        BpHook.__init__(self)
        self.begin_address         = address
        self.imm                   = Debugger()
        self.graph                 = Graph()
        self.draw                  = Draw()
        self.buf                   = []
        self.nodes_buf             = []
        self.nodes                 = []
        self.edges_buf             = []
        self.func_start            = None
        self.func_end              = None
        self.graph_handler         = None
        self.last_bb               = None
        self.hook_type             = hook_type
        self.first_func_finished   = False
        self.bb_end                = True
        self.node_count            = 0
        self.node_covered          = {}
        self.active_node           = ""
        
    #########################################################################    
    def run(self, regs):
        '''
        This is the main hook routine that occurs at [ESP] of a socket
        function call. It kicks off the whole process of sniffing the
        packet, graphing, and analyzing it.
        '''
        
        session = self.imm.getKnowledge("session")
        if session == True:
            self.imm.forgetKnowledge("session")
            self.imm.addKnowledge("session", False, force_add=0x1)
        else:
            self.imm.run()
            return
        
        
        # Now we determine what type of packet sniff we need to do
        if self.hook_type == "simple":
            if self.simple_packet_sniff(regs) == False:
                return
        else:
            if self.extended_packet_sniff(regs) == False:
                return
        
        # Make sure that the module has been analyzed.
        if self.imm.isAnalysed(self.begin_address) != 1:
            self.imm.analyseCode(self.begin_address)
        
        # Workaround for EIP == functionBegin address
        if self.begin_address == regs['EIP']:
            self.func_start = self.regs['EIP']
        else:
            self.func_start = self.imm.getFunctionBegin(self.begin_address)

        # Once we have the function information set some variables
        func            = self.imm.getFunction(self.func_start)
        self.func_end   = func.getEnd()
        func_name       = func.getName()

        # Setup the VCG header, add the first basic block and return
        self.start_graph(func_name)
            
        # Now we enter into a step-over routine where we will begin
        # tracing the execution/data flow of our packet, initialize the
        # code coverage counter beforehand
        self.imm.addKnowledge("code_coverage",0,force_add = 0x1)
        self.deep_analysis_loop(regs)
        
        # This stitches all the buffers together and splashes the graph
        self.render_graph()
        
        # We need to clear out the knowledgebase so let's grab the information 
        # we want to keep first
        boo_address     = self.imm.getKnowledge("boo_address")
        boo_port        = self.imm.getKnowledge("boo_port")
        test_port       = self.imm.getKnowledge("test_port")
        test_protocol   = self.imm.getKnowledge("test_protocol")
        
        # Disable the breakpoint or this hooer will get hit again
        #self.imm.disableBreakpoint(self.begin_address)        
        
        boo = boo_comm(boo_address,boo_port,test_port,test_protocol)
        boo.prepare_next_case()

                
        
        self.imm.run()
        # Give it some time to finish up any of its previous loops
        #packet.send_test_packet()
        
        
        
    #########################################################################
    def deep_analysis_loop(self, regs):
        '''
        This is the loop that steps the instruction pointer, determines
        branching decisions, and does the data analysis.
        '''
        
        loop_status     = True
                
        # We do the first instruction first, then enter a loop of stepping
        # to analyze the rest of the code paths
        self.imm.gotodisasmWindow(regs['EIP'])
        loop_status, processed_reg, step_type = self.opcode_processor(regs)
              
        # Begin the analysis loop, go grab a coffee this can take awhile
        while loop_status == True:
            
            # Determine whether we want to step over or in
            if step_type == "in":
                self.imm.stepIn()
            else:
                self.imm.stepOver()
            
            stepped_regs = self.imm.getRegs()           
            
            if self.imm.isAnalysed(stepped_regs['EIP']) != 1:
                   self.imm.analyseCode(stepped_regs['EIP'])
                   
            # Test if we landed inside a system DLL
            if self.test_system_dll(stepped_regs['EIP']) == True and self.first_func_finished == True or self.imm.isRunning() == True:
                break
            
            # The opcode processor does all of the dirty work
            loop_status, processed_reg, step_type = self.opcode_processor(stepped_regs)
            
        return
                
            
            
    #########################################################################       
    def opcode_processor(self, regs):    

       step_type       = "over"
       loop_status     = True
       
       
       # Grab the opcode from the address (EIP)
       opcode = self.imm.disasm(regs['EIP'])
       
       # Register the code coverage hit
       code_coverage = self.imm.getKnowledge("code_coverage")
       self.imm.forgetKnowledge("code_coverage")
       code_coverage += 1
       self.imm.addKnowledge("code_coverage",code_coverage,force_add=0x1)
       
       # For call instructions, if its calling into a non-system module
       # then we want to follow it. Otherwise the graph would explode.
       if opcode.isCall() == 1:
           if self.test_system_dll(opcode.jmpaddr) == False:
               step_type = "in"
        
       
       # The threshold is a way to prematurely terminate the analysis, otherwise
       # you can go wandering off in threading routines, garbage collection stuff, etc.
       # Break the loop if the threshold has been hit.
       threshold = self.imm.getKnowledge("threshold")
       
       if code_coverage >= threshold:
           loop_status = False
           
           
       if self.first_func_finished == True:
           
           # Now let's send the information off to our graphing function
           if self.bb_end == True:
               self.add_node_header(regs['EIP'])
               self.bb_end = False
           
           if opcode.isJmp() == 1 or opcode.isRet() == 1 or opcode.isConditionalJmp() == 1 or loop_status == False or step_type == "in":
               self.bb_end = True
               

           
           info_panel = self.imm.getInfoPanel()
           comment = self.imm.getComment(regs['EIP'])
           
           # Add the instructions, information and comments to the graph.                  
           self.add_node_instructions(regs['EIP'],opcode,comment,info_panel)
       
       # We want to step into RET instructions so that we correctly get
       # back to the callee
       if opcode.isRet() == 1:
           #self.imm.log("Ret Destination: 0x%08x" % opcode.jmpaddr)
                      
           if self.first_func_finished == False:
               self.first_func_finished = True
           
           if self.test_system_dll(opcode.jmpaddr) == True:
               loop_status = False    
       
       return loop_status, regs['EIP'], step_type
        
    
    #########################################################################
    def test_system_dll(self, address):        
        '''
        This function is designed to take an address and return whether
        it lies within a system DLL.
        '''
              
        jmp_module = self.imm.getModuleByAddress(address)
        
        if jmp_module is not None:
            system_dll = jmp_module.getIssystemdll()
            
            # We test here, as well the msvcr71.dll is really a system dll
            # but a lot of developers redistribute, treat it as such
            if system_dll == 1 or jmp_module.name.lower() == "msvcr71.dll": 
                return True
            else:
                return False
            
        return None
            
    #########################################################################   
    def start_graph(self, func_name):
        '''
        This just sets up the graphing header, and initializes the graphing routine.
        '''
        
        # Now we do a bunch of VCG lovin to get the graph setup the way we want it
        # this part of the code was taken directly from immvcglib.py and should not
        # be included as part of the judging criteria
        iteration = self.imm.getKnowledge("current_iteration")
        if iteration != 0 and iteration is not None:
            self.node_covered = self.imm.getKnowledge("node_covered")
        else:
            iteration = 0
            
        self.buf.append('graph: {\x0d\x0a')
        self.buf.append('title: "Packet Life (%s - Iteration: %d)"\r\n' % (self.imm.getDebuggedName(),iteration))
        self.buf.append("manhattan_edges: yes\r\n")
        self.buf.append("layoutalgorithm: mindepth\r\n")
        self.buf.append("finetuning: no\r\n")
        self.buf.append("layout_downfactor: 100\r\n")
        self.buf.append("layout_upfactor: 0\r\n")
        self.buf.append("layout_nearfactor: 0\r\n")
        self.buf.append("xlspace: 12\r\n")
        self.buf.append("yspace: 30\r\n")
        self.buf.append("display_edge_labels: yes\r\n")
        self.buf.append("colorentry 99: 193 255 193\r\n")
        self.buf.append("colorentry 100: 238 233 233\r\n")
        self.buf.append("colorentry 98: 255 69 0\r\n")
        self.buf.append("colorentry 97: 0 139 0\r\n")
        
    #########################################################################
    def add_node_header(self,address):        
        '''
        Adds the first node to the graph, this will be the function that called
        the receive socket operation.
        ''' 
        decode_address = self.imm.decodeAddress(address)
                
        # Start a new node by creating the header.
        if self.node_covered.has_key(address):
            self.active_node += 'node: { title: "%s" color: \f100 vertical_order: %d label:"\r\n\x0c31%s\x0c31\r\n\r\n' % (decode_address,self.node_count,decode_address)
        else:
            self.active_node += 'node: { title: "%s" color: \f99 vertical_order: %d label:"\r\n\x0c31%s\x0c31\r\n\r\n' % (decode_address,self.node_count,decode_address)
            self.node_covered[address] = True
                        
        self.nodes.append(decode_address)
        self.node_count += 1
    
    #########################################################################
    def add_node_instructions(self, address,opcode,comment=None,infopanel=None):        
        '''
        Adds the current instruction, associated comments and information.
        ''' 
        
        self.active_node += "\f310x%08x:  \f12%s\r\n" %       (address, opcode.result)
                   
        if comment is not None and comment != "":
            if opcode.isCall() == 1:
                self.active_node += "  \t\t\t\f98%s\r\n" % (comment.replace("\"", ""))
            else:
                self.active_node += "  \t\t\t\f01%s\r\n" % (comment.replace("\"", ""))
        
        if infopanel is not None and infopanel != "":
            # Here we do matching against the packet contents and 
            # what is registered in the infopanel
            self.data_match(opcode,infopanel)
        
        self.active_node += "\r\n"
        if self.bb_end == True:
            self.active_node += "\r\n\"}\r\n"
            self.last_bb = address
            self.nodes_buf.append(self.active_node)
            self.active_node = ""
        
    
    #########################################################################
    def data_match(self,opcode,infopanel):
        
        self.imm.log("In Data Match ++++++++++++++")
        
        matched = False
        sub_info   = []
        
        # Clean up the output a little
        for info in infopanel:
            if info != "":
                sub_info.append(info)
        
        for data in sub_info:
           
            if data.find("=") != -1:
                
                clean_data = data.split("=")[1]
        
                op_left = opcode.result.split(" ")[0]
                self.imm.log("Front Opcode: %s" % cmp)
                    
                # Check for the packet length
                packet_length = "%08x" % self.imm.getKnowledge("packet_length")
                
                self.imm.log("Comparing %s <-> %s" % (packet_length,clean_data))
                if clean_data.lower() == packet_length.lower():
                    self.active_node += "  \t\t\t\f08%s \f02(Packet Length)\r\n" % data.replace("\"","\\\"")
                    self.imm.log("Possible Packet Length Match++++++++++++++++++++++++++++")
                    matched = True
                
                if matched == False:    
                    ascii_packet     = self.imm.getKnowledge("ascii_packet")
                    binary_packet    = self.imm.getKnowledge("binary_packet")
                    
                    # Now let's begin matching the payload junk (I suck at this, many improvements can be made)
                    # Check for ASCII references
                    clean_data = data.split("ASCII")
                    self.imm.log("Cleaned Split: %s" % clean_data)
                    if clean_data != "" and clean_data[0] != data:
                        match = clean_data[1].replace("\"","").replace(")","").strip()
                        self.imm.log("MATCH: %s -------------------------------------------------" % match)
                        self.imm.log("PACKE: %s -------------------------------------------------" % ascii_packet)
                        if ascii_packet.rfind(match) != -1:
                            self.active_node += "  \t\t\t\f08%s \f09(Packet Payload)\r\n" % data.replace("\"","\\\"")
                            self.imm.log("Wooot========================================")
                            matched = True
                        
                # Now let's see if there is any binary matches such as ESI=41424344
                # again, not perfect but it should work well
                if matched == False:
                    clean_data = data.split("=")
                    if clean_data != "" and clean_data[0] != data:
                        
                        for bin in clean_data:
                            match = bin.replace("\"","").replace("(","").replace("[","").replace("]","").strip()
                            self.imm.log("MATCH: %s -------------------------------------------------" % match)
                            self.imm.log("PACKE: %s -------------------------------------------------" % binary_packet)
                            
                            if binary_packet.rfind(match) != -1 or binary_packet[::-1].rfind(match) != -1:
                                self.active_node += "  \t\t\t\f08%s \f97(Packet Payload)\r\n" % data.replace("\"","\\\"")
                                self.imm.log("Wooot========================================")
                                matched = True
                                
                # We didn't find any matches at all, output default info
                if matched == False:
                        self.active_node += "  \t\t\t\f08%s\r\n" % data.replace("\"","\\\"")
                        
            else:
                self.active_node += "  \t\t\t\f08%s\r\n" % data.replace("\"","\\\"")
                
                    
        
        
        
                                
                                
    #########################################################################
    def render_graph(self):
        '''
        This function assembles the nodes_buf and the edges_buf for the overall
        graph, and pushes it to the screen.
        '''    
        
        for a in range(0,len(self.nodes_buf)):
            self.buf.append(self.nodes_buf[a])
        
        self.buf.append("\r\n")
        for a in range(0,len(self.nodes)):
            if a < len(self.nodes)-1:
                self.buf.append('edge: { sourcename: "%s" targetname: "%s" color: darkgreen }\r\n' % (self.nodes[a],self.nodes[a+1]))
                        
        self.buf.append("\n}\r\n")
        
        # Send the graph back to Boo for storage
        boo_port        = self.imm.getKnowledge("boo_port")
        boo_address     = self.imm.getKnowledge("boo_address")
        test_port       = self.imm.getKnowledge("test_port")
        test_protocol   = self.imm.getKnowledge("test_protocol")
        iteration       = self.imm.getKnowledge("current_iteration")
        version         = self.imm.getModule(self.imm.getDebuggedName()).getVersion()
         
        s = socket(AF_INET,SOCK_STREAM)
       
        s.connect((boo_address,int(boo_port)))
        

        message = "graph|%s|%s|%d|%s|%d|%s||\r\n" % (self.imm.getDebuggedName(),version,int(test_port),test_protocol,int(iteration),"".join(self.buf))
        self.imm.log("%s" % message) 
        s.send(message)
         
         


        self.imm.addKnowledge("node_covered",     self.node_covered,force_add=0x1) 
        
    #########################################################################
    def simple_packet_sniff(self, regs):
        '''
        The simple packet sniff is one where we merely have a pointer
        to the buffer and a length. It's very easy to read the packets 
        out of memory.
        '''
        
        (payload_ptr, type, function_name) = self.imm.getKnowledge("%08x" % regs['EIP'])
        
        # The length is stored as a function return argument, so let's read EAX
        length = regs['EAX']
        
        try:
            # Because return codes can be -1 (error) we have to test for that.
            if length > 1 and length != 0xffffffff:
          
                counter = 0
                payload = ""
                bin_payload = ""
                
                # Get the raw packet payload and the length of the bytes
                raw_payload = self.imm.readMemory(payload_ptr, length)                     
                pack_len = str(length)+"c"
                
                if raw_payload is not None:
                    
                    final_payload = struct.unpack(pack_len, raw_payload)
        
                    # Iterate through the unpacked string, only outputting printable 
                    # ascii characters, output the standard dots if non-printable
                    while counter < int(length):
                        if ord(final_payload[counter]) >= 32 and ord(final_payload[counter]) <= 126:
                            payload += final_payload[counter]
                        else:
                            payload += "."
                        
                        bin_payload += "%02x" % ord(final_payload[counter])
                        counter += 1
                        
                    # Build the list thats table-friendly
                    log_items = [function_name, type, "%d" % int(length), bin_payload[:512], payload[:512]]
    
                    # Add the packet to the knowledgebase
                    self.imm.addKnowledge("binary_packet", bin_payload, force_add=0x1)
                    self.imm.addKnowledge("ascii_packet",  payload, force_add=0x1)
                    self.imm.addKnowledge("packet_length", int(length[0]),force_add=0x1)
    
                    # Get a handle to the window and add the items, along with the related
                    # address, this is sweet cause you can double-click on a packet and 
                    # see in the disassembly where it was sent/received :)
                    cap_win = self.imm.getKnowledge("cap_win")
                    cap_win.add(regs['EIP'], log_items)
                    
                    #self.imm.disableBreakpoint(regs['EIP'])
        except:
                return False
            
    #########################################################################            
    def extended_packet_sniff(self, regs):
        '''
        This is for the WSA* family of socket functions where we have to
        do more pointer manipulation and there's a bit more work involved
        in getting the packets.
        '''
 
        (payload_ptr, recv_ptr, type, function_name) = self.imm.getKnowledge("%08x" % regs['EIP'])
        
        # This is an [out] pointer that let's us know how much data was
        # received on a socket (non-overlapped)               
        length = self.imm.readMemory(recv_ptr, 4)
        length = struct.unpack("l", length)
        
        try:
            # Network apps are chatty, we don't want to grab garbage packets
            if length[0] > 1:
          
                counter = 0
                payload = ""
                bin_payload = ""
               
                # Get the raw packet payload and the length of the bytes
                raw_payload = self.imm.readMemory(payload_ptr, int(length[0]))
                pack_len = str(int(length[0]))+"c"
                
                if raw_payload is not None:
                    
                    final_payload = struct.unpack(pack_len, raw_payload)
        
                    # Iterate through the unpacked string, only outputting printable 
                    # ascii characters, output the standard dots if non-printable
                    while counter < int(length[0]):
                        if ord(final_payload[counter]) >= 32 and ord(final_payload[counter]) <= 126:
                            payload += final_payload[counter]
                        else:
                            payload += "."
                        
                        bin_payload += "%02x" % ord(final_payload[counter])
                        counter += 1
                        
                    # Build the list thats table-friendly
                    log_items = [function_name, type, "%d" % int(length[0]), bin_payload[:512], payload[:512]]
    
                    # Add the packet to the knowledgebase
                    self.imm.addKnowledge("binary_packet", bin_payload, force_add=0x1)
                    self.imm.addKnowledge("ascii_packet",  payload, force_add=0x1)
                    self.imm.addKnowledge("packet_length", int(length[0]),force_add=0x1)
                    
                    # Get a handle to the window and add the items, along with the related
                    # address, this is sweet cause you can double-click on a packet and 
                    # see in the disassembly where it was sent/received :)
                    cap_win = self.imm.getKnowledge("cap_win")
                    cap_win.add(regs['EIP'], log_items)  
                    
                    #self.imm.disableBreakpoint(regs['EIP'])
        except:
            return False
#############################################################################
class set_hooks(LogBpHook):
    
    #########################################################################
    def __init__(self):
        
        LogBpHook.__init__(self)
        self.imm        =    Debugger()
        
        
    #########################################################################
    def create_hooks(self):
        '''
        This creates the original hooks on the common socket receive functions,
        this is not comprehensive but it should catch most socket operations. 
        Future enhancements will include all possible socket operations.
        '''
        
        ws_wsarecv     =                     self.imm.getAddress("ws2_32.WSARecv")
        ws_wsasend     =                     self.imm.getAddress("ws2_32.WSASend")
        ws_recv        =                     self.imm.getAddress("ws2_32.recv")
        ws_recvfrom    =                     self.imm.getAddress("ws2_32.recvfrom") 
    
        # Set the hooks
        current_iteration = self.imm.getKnowledge("current_iteration")
        if current_iteration == 0:
            self.add("WSARecv", ws_wsarecv)
            self.add("WSASend", ws_wsasend)
            self.add("recv", ws_recv)
            self.add("recvfrom", ws_recvfrom)
                
        # Register the hook-address pair with the knowledgebase
        self.imm.addKnowledge("%08x" % ws_wsarecv, "WSARecv",force_add=0x1)
        self.imm.addKnowledge("%08x" % ws_wsasend, "WSASend",force_add=0x1)
        self.imm.addKnowledge("%08x" % ws_recv, "recv",force_add=0x1)
        self.imm.addKnowledge("%08x" % ws_recvfrom, "recvfrom",force_add=0x1)     
        
    #########################################################################
    def retrieve_packet(self, function_name, regs):
        '''
        This function determines how to handle the packet data. Some socket 
        operations require more work (such as WSARecv), and others less (recv).
   
        If necessary this function will register a hook on [ESP], where any
        [out] pointers from a function will be set.
        '''        
        
        extended_hook = None
        
        # Determine what function we have hooked, based on this, retrieve the packet contents
        if function_name == "WSARecv":        
            type = PACKET_TYPE_RECV+PACKET_PROTOCOL_TCP
            extended_hook = True
        
        if function_name == "WSASend":
            type=PACKET_TYPE_SEND+PACKET_PROTOCOL_TCP
            extended_hook = True
        
        if function_name == "recvfrom":
            type=PACKET_TYPE_RECV+PACKET_PROTOCOL_UDP
            extended_hook = False
              
        if function_name =="recv":
            type=PACKET_TYPE_RECV+PACKET_PROTOCOL_TCP
            extended_hook = False

        if extended_hook is None:
            self.imm.addKnowledge("session", False, force_add=0x1)
            return

        # An extended hook requires a bit more work to pull out the packet info
        if extended_hook == True:
            
            # Get the pointer to the payload pointer :(
            pbuffer_ptr = self.imm.readMemory(regs['ESP'] + 8, 4)
            pbuffer_ptr = struct.unpack("L", pbuffer_ptr)
                                    
            # Get the pointer to the packet payload
            payload_ptr = self.imm.readMemory(pbuffer_ptr[0]+4, 4)
            payload_ptr = struct.unpack("<L", payload_ptr)
                        
            # Get the [out] pointer of the received bytes
            recv_ptr = self.imm.readMemory(regs['ESP'] + 0x10, 4)
            recv_ptr = struct.unpack("L", recv_ptr)
                                    
            # Figure out [esp]
            esp_ptr = self.imm.readMemory(regs['ESP'], 4)
            esp_ptr = struct.unpack("<L", esp_ptr)
                        
            # Now we hook [esp] if this isn't the first iteration, don't reset the hook
            ret_hook = packet_analyzer(esp_ptr[0], "ext_hook")
            ret_hook.add("%08x" % esp_ptr[0], esp_ptr[0])
                   
            # Add this ret hook to the knowledgebase
            self.imm.addKnowledge("%08x" % esp_ptr[0], (payload_ptr[0], recv_ptr[0], type, function_name),force_add=0x1)
            
        else:
            
            # Get the pointer to the buffer
            payload_ptr = self.imm.readMemory(regs['ESP'] + 8, 4)
            payload_ptr = struct.unpack("L", payload_ptr)
            
            # Figure out where [ESP] points to
            esp_ptr = self.imm.readMemory(regs['ESP'], 4)
            esp_ptr = struct.unpack("<L", esp_ptr)
            
            # Add the [ESP] hook for when the function returns
        
            simple_hook = packet_analyzer(esp_ptr[0], "simple")
            simple_hook.add("%08x" % esp_ptr[0], esp_ptr[0])
                
            # Add our pertinent information to the knowledgebase
            self.imm.addKnowledge("%08x" % esp_ptr[0], (payload_ptr[0], type, function_name),force_add=0x1)
        
        
                 
    #########################################################################
    def run(self, regs):
        '''
        This routine is the first one hit, when a socket operation occurs.
        '''
        
        # Determine if we are in the middle of an analysis session
        session = self.imm.getKnowledge("session")  
                    
        # Retrieve the function name 
        function_name = self.imm.getKnowledge("%08x" % regs['EIP'])
        
        # Clear the breakpoint
        self.retrieve_packet(function_name, regs)    
        

class boo_comm():
    
    def __init__(self,boo_address,boo_port,test_port,test_protocol):
               
        self.imm             = Debugger()
        self.boo_address     = boo_address
        self.boo_port        = int(boo_port)
        self.boo_sock        = socket(AF_INET,SOCK_STREAM)
        self.test_port       = int(test_port)
        self.test_protocol   = test_protocol
        
    def notify(self,message):
        
        self.imm.log("Boo Port: %d Boo Address: %s" % (self.boo_port,self.boo_address))
        
        if message == "begin_test":
            self.imm.addKnowledge("session", True, force_add=0x1)
            
            message = message + "|" + str(self.test_port) + "|" + self.test_protocol
            
            try:
                self.boo_sock.connect((self.boo_address,self.boo_port))
            except:
                self.imm.log("Couldn't connect to Boo! Poor thing...")
                return
            # We notify boo we are ready to begin

        # Double pipe is our delimiter
        message = message + "||\r\n"    

        
        self.boo_sock.send(message)
        
        self.boo_sock.close()
       
            
        
    def prepare_next_case(self):
        
        # We need to clear the knowledgebase so grab the packet first, as well the capture window
        binary_packet     = self.imm.getKnowledge("binary_packet")
        ascii_packet      = self.imm.getKnowledge("ascii_packet")
        code_coverage     = self.imm.getKnowledge("code_coverage")
        current_iteration = self.imm.getKnowledge("current_iteration")
        threshold         = self.imm.getKnowledge("threshold")
        new_threshold     = threshold + 25

        # Now re-add the information in a list called iteration
        self.imm.addKnowledge("iteration_%d" % current_iteration, (code_coverage,binary_packet,ascii_packet),force_add=0x1)
        
        # Output some test results    
        self.imm.log("=====================================================")
        self.imm.log("Test Results for Iteration: %d" % current_iteration)
        self.imm.log("")
        self.imm.log("Code Coverage: %d (Threshold %d)" % (code_coverage,threshold))
        self.imm.log("Binary Packet: %s" % binary_packet)
        self.imm.log("ASCII Packet:  %s" % ascii_packet)
        self.imm.log("")
        self.imm.log("Increasing Threshold to: %d" % new_threshold)
        self.imm.log("=====================================================")
                
        
        
        # Track the iteration number
        self.imm.addKnowledge("threshold",        new_threshold, force_add=0x1)
        
        current_iteration += 1
        self.imm.addKnowledge("current_iteration", current_iteration, force_add=0x1)
        self.imm.run()
    

       
#############################################################################
def usage(imm):
    '''
    Prints the usage information for this pycommand.
    '''
    
    imm.log("!mike BOOADDRESS BOOPORT TESTPORT PROTOCOL - Sulley's best friend, it analyzes a protocol and outputs graphs and Sulley scripts. Get the process running first!")
    imm.log("eg. !mike 192.168.7.1 1337")

    

#############################################################################
def main(args):
    '''
    This is the main routine when a PyCommand is run. This creates the window object,
    sets the hooks and then fires out a test packet.
    '''
    
    imm = Debugger()
    # Check commandline args, I hate this part :)
    if not args:
        usage(imm)
        return "Usage information outputted please check the log window"
        
    imm.ignoreSingleStep("CONTINUE")
    
    # Create the packet capture window
    column_titles = ["Function", "Type", "Length", "Binary", "ASCII"]
    cap_win = imm.createWindow("Captured Packets", column_titles)
    
    # Add the window to the knowledge base, and monitor whether the 
    # analysis session is active
    imm.addKnowledge("cap_win", cap_win, force_add=0x1)

    
    # Set the hooks on the socket operations.
    try:
        hooker = set_hooks()
        hooker.create_hooks()
    
    except:
        
        return "Can't find exported socket functions."
    
    # Track the iteration number
    imm.addKnowledge("current_iteration", 0, force_add = 0x1)
    
   
    # We kick the testing off by using a known test packet to begin
    # the attempt at reversing the protocol
    boo_address   = args[0] 
    boo_port      = args[1]
    test_port     = args[2]
    test_protocol = args[3]
    threshold     = 50
    
    imm.addKnowledge("boo_address",        boo_address,force_add=0x1)
    imm.addKnowledge("boo_port",           boo_port,force_add=0x1)
    imm.addKnowledge("threshold",          threshold,force_add=0x1)
    imm.addKnowledge("test_port",          test_port,force_add=0x1)
    imm.addKnowledge("test_protocol",      test_protocol,force_add=0x1)
    
    boo = boo_comm(boo_address,boo_port,test_port,test_protocol)
    boo.notify("begin_test")
    
    return "Network hooks in place."



