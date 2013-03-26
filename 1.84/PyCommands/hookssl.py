import socket
import struct
import xmlrpclib
import traceback
import base64
from immlib import *
from immutils import *
import getopt

DESC="""Creates a table that displays packets received on the network."""

 
#############################################################################
class set_hooks(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)
        self.xmlhost          = ""
        self.xmlport          = 0
        return 
    #########################################################################
    def run(self,regs):
        '''
        This routine is the first one hit, when a socket operation occurs.
        '''
        imm = Debugger()
        
                
        # Retrieve the function name 
        function_name = imm.getKnowledge("%08x" % regs['EIP'])
        imm.log("Hook hit for %s"%function_name)
        self.retrieve_packet(imm,function_name,regs)    
        return 
                
    #########################################################################
    def retrieve_packet(self,imm,function_name,regs):
        '''
        This function logs the packet data into cap_win
        '''
        imm.log("Retrieving packet from %s"%function_name)    
        # Determine what function we have hooked, based on this, retrieve the packet contents
        if function_name == "SSL3DecryptMessage":
            #nothing yet
            return 
        elif function_name == "SSL3EncryptMessage":        
            imm.log("Looking at SSL3EncryptMessage data")
            #The payload ptr is at esp+24
            pbuffer_ptr = imm.readMemory( regs['ESP'] + 0x24, 4)
            pbuffer_ptr = int(struct.unpack("L", pbuffer_ptr)[0])
            
            #the size of the buffer is at esp+0x20
            pbuffer_len = imm.readMemory( regs['ESP'] + 0x20, 4)
            pbuffer_len = int(struct.unpack("L", pbuffer_len)[0])
            
            imm.log("pbuffer_Size=%d"%pbuffer_len)
            #imm.log("Buffer Location: 0x%08x" % pbuffer_ptr[0])
            imm.log("pbuffer_ptr=%s"%repr(pbuffer_ptr))
            # Get the pointer to the packet payload
            payload = imm.readMemory(pbuffer_ptr, pbuffer_len)
            imm.log("Payload=%s"%repr(payload))
            #payload= "Payload!"
            decoded_payload = ""
            # Build the list thats table-friendly
            log_items = [function_name,repr(payload),decoded_payload]

            # Get a handle to the window and add the items, along with the related
            # address, this is sweet cause you can double-click on a packet and 
            # see in the disassembly where it was sent/received :)

            
            #save this data to a file called payloads.txt
            #file("payloads.txt","ab").write(repr(payload)+"\n")
        using_xml_rpc = False
        
        if self.xmlport != 0:
            server = xmlrpclib.ServerProxy("http://%s:%d/"%(self.xmlhost,self.xmlport), allow_none=True)
            imm.log("Using server: %s:%d"%(self.xmlhost, self.xmlport))
            using_xml_rpc = True
        else: 
            server = None 
        
        if using_xml_rpc:
            #send our xml request to the remove side
            #if self.filter matches...(stub for now)
            try:
                result = server.senddata(("ssldata",[base64.encodestring(payload)]))
            except:
                data=traceback.format_exc()
                imm.log("Failed to connect to remote server, sorry")
                imm.logLines("Error was: %s"%data)
                return
            
            #Now parse what we got back - a command and list of arguments
            command, arguments = result
            if command=="LEAVEALONE":
                imm.log("Leaving alone")
                return 
            elif command=="REPLACE":
                payload=arguments[0]
                payload=base64.decodestring(payload) #decode it
                imm.log("New Payload recved: %s"%repr(payload))
                
                #they encrypt messages in place, so we need to use their original
                #buffer to put our message into.
                #The payload ptr is at esp+24
                pbuffer_ptr = imm.readLong( regs['ESP'] + 0x24)
                imm.log("Replacing buffer at %8.8x with data of length %d"%(pbuffer_ptr, len(payload)))
                imm.writeMemory(pbuffer_ptr, payload)
                
                
            #add more commands from XML-RPC here
                

            
        return 
            
def usage(imm):       
    imm.log("!hookssl.py")
    imm.log("-D               (to uninstall hook)")
    imm.log("-s host:port     (Server to send XML-RPC data to)")
    imm.log("-h This help")
    return 

# The main routine that gets run when you type !packets
def main(args):

    imm = Debugger()
    imm.ignoreSingleStep("CONTINUE")
    try:
        opts,argo = getopt.getopt(args, "Dhs:")
    except:
        return usage(imm)
    xmlhost=""
    xmlport=0
    for o,a in opts:
        if o == "-D":
            hooker=imm.getKnowledge("ssl3hook")
            if not hooker:
                imm.log("Could not find hook to delete!")
                return "Did not find hook to delete"
            imm.removeHook("SSL 3 Encrypt Message")
            imm.removeHook("SSL 3 Decrypt Message")
            #now forget about that hook
            imm.forgetKnowledge("ssl3hook")
            return "Unhooked our ssl3hook"
        if o == "-s":
            xmlhost,xmlport = a.split(":")
            xmlport=int(xmlport)
        if o =="-h":
            return usage(imm)

    hooker = set_hooks()
    hooker.xmlhost=xmlhost
    hooker.xmlport=xmlport
    
    
    # Find the addresses of the functions we want to hook
    # Then register the hooks
    ssl3encryptmessage     = imm.getAddress("schannel._Ssl3EncryptMessage@12")
    imm.log("SSL3 Encrypt Message found at 0x%x"%ssl3encryptmessage)
    if ssl3encryptmessage == -1:
        imm.log("Could not locate ssl3encryptmessage")
        return "Failed to find address to hook!"

    ssl3decryptmessage     = imm.getAddress("schannel._Ssl3DecryptMessage@12")
    imm.log("SSL3 Decrypt Message found at 0x%x"%ssl3encryptmessage)
    if ssl3decryptmessage == -1:
        imm.log("Could not locate ssl3encryptmessage")
        return "Failed to find address to hook!"

        
    # Set the hooks
    ret=hooker.add("SSL 3 Encrypt Message",  ssl3encryptmessage)
    ret=hooker.add("SSL 3 Decrypt Message",  ssl3decryptmessage)
    imm.addKnowledge("ssl3hook",hooker)
    imm.log("Hooker.add returned %s"%ret)
    if ret==-1:
        imm.log("Hooker add failed! :<")
        return "Failed to add hook!"
    # Register the hook-address pair with the knowledgebase
    imm.addKnowledge("%08x" % ssl3encryptmessage,     "SSL3EncryptMessage")
    imm.addKnowledge("%08x" % ssl3decryptmessage,     "SSL3DecryptMessage")
    return "Network hooks in place."


