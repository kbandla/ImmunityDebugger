import socket
import struct

from immlib import *


DESC="""Creates a table that displays packets received on the network."""

#############################################################################
'''
Some defines for re-use.
'''
PACKET_TYPE_SEND        =    "Send "
PACKET_TYPE_RECV        =    "Recv "
PACKET_PROTOCOL_UDP     =    "(UDP)"
PACKET_PROTOCOL_TCP     =    "(TCP)"


#############################################################################
class simple_hooks(LogBpHook):

    #########################################################################
    def __init__(self):
        LogBpHook.__init__(self)
    
    
    #########################################################################    
    def run(self,regs):
        
        imm = Debugger()
        
        (payload_ptr,type,function_name) = imm.getKnowledge("%08x" % regs['EIP'])
        
        # The length is stored as a function return argument, so let's read EAX
        length = regs['EAX']
        
                
        # Because return codes can be -1 (error) we have to test for that.
        if length > 1 and length != 0xffffffff:
      
            counter = 0
            payload = ""
            bin_payload = ""
            
            # Get the raw packet payload and the length of the bytes
            raw_payload = imm.readMemory(payload_ptr,length)
            
            
            
            pack_len = str(length)+"c"
            imm.log("Pack Len: %s " % pack_len)
            if raw_payload is not None:
                
                final_payload = struct.unpack(pack_len,raw_payload)
    
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
                log_items = [function_name,type,"%d" % int(length),bin_payload[:512],payload[:512]]

                # Get a handle to the window and add the items, along with the related
                # address, this is sweet cause you can double-click on a packet and 
                # see in the disassembly where it was sent/received :)
                cap_win = imm.getKnowledge("cap_win")
                cap_win.add(regs['EIP'],log_items)
                
        # Drop the entry in the KB, disable the BP, and unHook.  
        imm.forgetKnowledge("%08x" % regs['EIP']) 
        imm.disableBreakpoint(regs['EIP'])   
        self.UnHook()
        
        
#############################################################################
class ext_hooks(LogBpHook):
   
   
    #########################################################################
    def __init__(self):
        LogBpHook.__init__(self)
   
    
    #########################################################################
    def run(self,regs):    

        imm = Debugger()
               
        (payload_ptr,recv_ptr,type,function_name) = imm.getKnowledge("%08x" % regs['EIP'])
        
        # This is an [out] pointer that let's us know how much data was
        # received on a socket (non-overlapped)               
        length = imm.readMemory(recv_ptr,4)
        length = struct.unpack("l",length)
        
        # Network apps are chatty, we don't want to grab garbage packets
        if length[0] > 1:
      
            counter = 0
            payload = ""
            bin_payload = ""
           
            # Get the raw packet payload and the length of the bytes
            raw_payload = imm.readMemory(payload_ptr,int(length[0]))
            pack_len = str(int(length[0]))+"c"
            
            if raw_payload is not None:
                
                final_payload = struct.unpack(pack_len,raw_payload)
    
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
                log_items = [function_name,type,"%d" % int(length[0]),bin_payload[:512],payload[:512]]

                # Get a handle to the window and add the items, along with the related
                # address, this is sweet cause you can double-click on a packet and 
                # see in the disassembly where it was sent/received :)
                cap_win = imm.getKnowledge("cap_win")
                cap_win.add(regs['EIP'],log_items)  
                
                
        # Drop the entry in the KB, disable the BP, and unHook.  
        imm.forgetKnowledge("%08x" % regs['EIP']) 
        imm.disableBreakpoint(regs['EIP'])   
        self.UnHook()

 
#############################################################################
class set_hooks(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)
                
    #########################################################################
    def run(self,regs):
        '''
        This routine is the first one hit, when a socket operation occurs.
        '''
        imm = Debugger()
        
                
        # Retrieve the function name 
        function_name = imm.getKnowledge("%08x" % regs['EIP'])
        
        self.retrieve_packet(imm,function_name,regs)    
    
                
    #########################################################################
    def retrieve_packet(self,imm,function_name,regs):
        '''
        This function determines how to handle the packet data. Some socket 
        operations require more work (such as WSARecv), and others less (recv).
   
        If necessary this function will register a hook on [ESP], where any
        [out] pointers from a function will be set.
        '''
            
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
       
            # An extended hook requires a bit more work to pull out the packet info
        if extended_hook == True:
           
            # Get the pointer to the payload pointer :(
            pbuffer_ptr = imm.readMemory( regs['ESP'] + 8, 4)
            pbuffer_ptr = struct.unpack("L", pbuffer_ptr)
            #imm.log("Buffer Location: 0x%08x" % pbuffer_ptr[0])
                        
            # Get the pointer to the packet payload
            payload_ptr = imm.readMemory(pbuffer_ptr[0]+4,4)
            payload_ptr = struct.unpack("<L", payload_ptr)
            #imm.log("Payload Pointer: %08x" % payload_ptr[0])
            
            # Get the [out] pointer of the received bytes
            recv_ptr = imm.readMemory(regs['ESP'] + 0x10, 4)
            recv_ptr = struct.unpack("L",recv_ptr)
            #imm.log("Receive Pointer: %08x" % recv_ptr[0])
                        
            # Figure out [esp]
            esp_ptr = imm.readMemory(regs['ESP'],4)
            esp_ptr = struct.unpack("<L", esp_ptr)
            #imm.log("[ESP] at 0x%08x" % esp_ptr[0])
            
            # Now we hook [esp]
            ret_hook = ext_hooks()
            ret_hook.add("%08x" % esp_ptr[0],esp_ptr[0])
            
            # Add this ret hook to the knowledgebase
            imm.addKnowledge("%08x" % esp_ptr[0],(payload_ptr[0],recv_ptr[0],type,function_name))
        
        else:
            
            # Get the pointer to the buffer
            payload_ptr = imm.readMemory(regs['ESP'] + 8, 4)
            payload_ptr = struct.unpack("L", payload_ptr)
            
            # Figure out where [ESP] points to
            esp_ptr = imm.readMemory(regs['ESP'],4)
            esp_ptr = struct.unpack("<L", esp_ptr)
            
            # Add the [ESP] hook for when the function returns
            simple_hook = simple_hooks()
            simple_hook.add("%08x" % esp_ptr[0],esp_ptr[0])
            
            # Add our pertinent information to the knowledgebase
            imm.addKnowledge("%08x" % esp_ptr[0],(payload_ptr[0],type,function_name))
            
            
# The main routine that gets run when you type !packets
def main(args):

    imm = Debugger()
    imm.ignoreSingleStep("CONTINUE")
    hooker = set_hooks()

    # Create the packet capture window
    column_titles = ["Function","Type","Length","Binary","ASCII"]
    cap_win = imm.createWindow("Captured Packets", column_titles )
    
    # Add the window to the knowledge base
    imm.addKnowledge("cap_win", cap_win,force_add=0x1)
    
    # Find the addresses of the functions we want to hook
    # Then register the hooks
    ws_wsarecv     = imm.getAddress("ws2_32.WSARecv")
    ws_wsasend     = imm.getAddress("ws2_32.WSASend")
    ws_recv        = imm.getAddress("ws2_32.recv")
    ws_recvfrom    = imm.getAddress("ws2_32.recvfrom") 
    
    # Set the hooks
    hooker.add("WSARecv",     ws_wsarecv)
    hooker.add("WSASend",     ws_wsasend)
    hooker.add("recv",        ws_recv)
    hooker.add("recvfrom",    ws_recvfrom)
    
    
    # Register the hook-address pair with the knowledgebase
    imm.addKnowledge("%08x" % ws_wsarecv,     "WSARecv")
    imm.addKnowledge("%08x" % ws_wsasend,     "WSASend")
    imm.addKnowledge("%08x" % ws_recv,        "recv")
    imm.addKnowledge("%08x" % ws_recvfrom,    "recvfrom")
    
         
    return "Network hooks in place."


