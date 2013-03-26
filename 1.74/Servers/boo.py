import asyncore
import asynchat
import os
import string
import socket




# Globally track all test clients
test_clients = {}

class boo_channel(asynchat.async_chat):

    def __init__(self, server, sock, addr):
        asynchat.async_chat.__init__(self, sock)
        self.set_terminator("||")
        self.data = ""
        self.shutdown = 0
        self.remote_address = addr
        
    def collect_incoming_data(self, data):
        self.data = self.data + data
        

    def found_terminator(self):
        
        
        print self.data
        
        message = self.data.split("|")
        # Now depending on what mike has sent us, we want to take certain actions
        # First case is that we are ready on the ID side to begin testing
        # Let's pick a port and protocol to munge!
        if message[0] == "begin_test":
        
            # Add the client to the global list of test subjects
            global test_clients
            test_clients[self.remote_address[0]] = (message[1],message[2])
            print test_clients
            print "[*] Received test begin request from %s." % self.remote_address[0]
            
            # Create the test packet which begins our analysis
            if message[2] == "tcp":
                s = socket(AF_INET,SOCK_STREAM)
                s.connect((self.remote_address[0],int(message[1])))
                
                # If this thing is bannerable we need some kind of logic here
                # to handle it. Possible a loop?
                #test = s.recv(1024)
                #print test
                
            else:
                s = socket(AF_INET,SOCK_DGRAM)
            
            test_buffer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnop\r\n"
            s.send(test_buffer)
            
            print "[*] Sent %s a test packet of: %s" % (self.remote_address[0],test_buffer)
            
            self.set_terminator("||")
            self.close_when_done()
        
        # We are receiving a graph from Mike, put it in the appropriate 
        # directory with a date, easy of use for trapping different patched
        # versions of software
        if message[0] == "graph":
            
            print self.data
            print "[*] Mike is Sending a Graph From: %s" % self.remote_address[0]
            
            # Now we create a directory structure to hold our graphs and other shizzle
            dir             = message[1].split(".")[0]
            version_dir     = message[2].replace(".","_")
            host_dir        = self.remote_address[0]+"_"+message[4]+"_"+message[3]
            host_dir        = host_dir.replace(".","_")
            iteration_number= message[5]
            # Create the parent directory based on the binary name
            try:
                os.mkdir(dir)                
            except:
                pass
            
            # Create the first child based on the binary version
            try:
                os.mkdir(dir+"\\\\"+version_dir)
            except:
                pass
            
            # Create the second child based on the test machine that 
            # send the graph
            try:
                os.mkdir(dir+"\\\\"+version_dir+"\\\\"+host_dir)
            except:
                pass
            
            # Now write out the graph
            filename = dir+"\\\\"+version_dir+"\\\\"+host_dir+"\\\\iteration_"+str(iteration_number)+".gdl"
            
            fd=open(filename,"wb")
            
            # Clean up the graph output
            graph = "%s" % message[6]
                       
            
            fd.write(graph)
            
            fd.close()
            
            
            
        
        
        # Clean up after ourselves
        del message
        
            
            
            
class boo_server(asyncore.dispatcher):

    def __init__(self, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(AF_INET, SOCK_STREAM)
        self.bind(("", port))
        self.listen(5)

    def handle_accept(self):
        conn, addr = self.accept()
        boo_channel(self, conn, addr)

#
# try it out
PORT = 9000
s = boo_server(PORT)
print "[*] Boo Listening for Mike Calling on:", PORT, "..."
asyncore.loop()

