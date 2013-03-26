#!/usr/bin/env python
"""
ssl Listener - for hookssl.py client-side

Use this like:
/home/me/ImmunityDebugger/ $ python Servers/ssl_listener.py 5555

"""
import sys
from threading import Thread
import time
import SimpleXMLRPCServer
import threading
import base64
import traceback
import StringIO
import gzip 
import re
if "." not in sys.path: sys.path.append(".")
from Libs.immutils import *

#Lots of people see a problem and think "I know, I'll use a regular expression!" - now they have two problems
#dict of compiled and text re's and what we replace it with
#don't forget to xmlencode this stuff first.
txtresdict={}
#txtresdict["something"]="somethingelse"

#now make tuple of (compiled re, replace with)
for tre in txtresdict:
    p=re.compile(tre)
    txtresdict[tre]=(p, txtresdict[tre])
    

def gunzipstring(data):
    """
    Gunzip's a string, or throws an exception
    """
    datastream=StringIO.StringIO(data)
    g=gzip.GzipFile(fileobj=datastream)
    data=g.read()
    return data

def gzipstring(data):
    """
    Gzip's a string to another string using StringIO
    """
    datastream=StringIO.StringIO()
    g=gzip.GzipFile(mode="w",fileobj=datastream)
    g.write(data)
    g.close()
    ret=datastream.getvalue()
    return ret

CHARS16TEXT="\x9a" #+ intel_short(length) + string
CHARS8WITHENDELEMENT="\x99" #+ ord(len(string))+string
CHAR8TEXT="\x98"
EMPTYTEXTRECORD="\xa8" #good for padding
ENDELEMENT="\x01"
def count_end_elements(data, getdata=False ):
    """
    Parses the packet starting at the first data string
    either returns the number of end elements or the 
    original data string (still base64 and gziped)
    """
    end_elements=0
    retdata=[]
    #print "NBFX parsing: %s"%repr(data)
    while data!="":
        if data[0]==CHARS16TEXT:
            length=istr2halfword(data[1:3])
            newdata=data[3:3+length]
            data=data[3+length:]
            retdata+=[newdata]
        elif data[0] in [CHAR8TEXT, CHARS8WITHENDELEMENT]:
            if data[0]==CHARS8WITHENDELEMENT:
                end_elements+=1
            length=ord(data[1])
            newdata=data[2:2+length]
            data=data[2+length:]
            retdata+=[newdata]
        elif data[0]==ENDELEMENT:
            data=data[1:]
            end_elements+=1
        else:
            print "end_elements not able to parse %2.2x"%ord(data[0])
    if getdata:
        return "".join(retdata)
    return end_elements

def parse_NBFS(payload):
    """
    Parse (badly) NBFS/X to get the gziped data out
    """
    #print "Parsing NBFS of %d length"%len(payload)

    start=payload.find("Compression\x9a")
    if start=="-1":
        return "" #failed
    
    start=start+len("Compression")
    #copy all the new data in there
    base64edzipeddata=count_end_elements(payload[start:], getdata=True)
    #print "base64 bziped data: %s"%repr(base64edzipeddata)
    base64data=""
    try:
        base64data=base64.decodestring(base64edzipeddata)
    except:
        pass 

    if base64data=="":
        print "Nothing to decode in gzip"
        return ""#nothing to decode 

    gzip_decoded=""
    try: 
        gzip_decoded=gunzipstring(base64data)
        #print "GZip decoded"
    except:
        traceback.print_exc(file=sys.stdio)
        pass 

    if gzip_decoded!="":
        print "Gzip Data found: %s"%repr(gzip_decoded)
        return gzip_decoded
    return ""
    

def replace_NBFS(payload, decoded_payload):
    """
    Takes original code and base64 gzip decoded payload
    """
    data_to_add=base64.encodestring(gzipstring(decoded_payload)).strip()
    start=payload.find("Compression\x9a")
    if start=="-1":
        return "" #failed
    
    start=start+len("Compression")
    #copy all the new data in there
    end_elements=count_end_elements(payload[start:])
    #print "End elements found: %d"%end_elements
    newdata=payload[:start]

    #now our new payload - we only add payloads of 256 bytes or less.
    #not sure why the server hates larger payloads, but it does.
    while data_to_add!="":
        d=data_to_add[:256]
        newdata+=CHARS16TEXT+intel_short(len(d))+d
        data_to_add=data_to_add[256:]
        
    #now end all elements we need to end
    newdata+=ENDELEMENT*end_elements 
    #now pad out forever
    newdata+=EMPTYTEXTRECORD*1000 
    newdata=newdata[:len(payload)]
    print "Olddata(%d)=%s"%(len(payload),repr(payload))
    print "Newdata(%d)=%s"%(len(newdata),repr(newdata))
    return newdata

    
class listener_thread(Thread):
    """
    This object keeps a thread running for the XML-RPC server to use. Because
    we use Timeoutsocket, we need to handle socket accept timeouts, which is 
    nice because that way we can also be halted.
    """
    def __init__(self, server, debugger_object):
        self.debugger=debugger_object
        self.server=server 
        Thread.__init__(self)
        self.setDaemon(True)
        self.state="Setup"
        return 
    
    def run(self):
        self.state="Running"
        while 1:
            if self.state=="HALT":
                return 
            try:
                self.server.serve_forever()
            #except timeoutsocket.Timeout:
            #    pass 
            except:
                #interupted system call...ignore...(essentially timeout)
                pass
            
            

    def halt(self):
        self.state="HALT"
        return 
    
class listener_instance(object):
    """
    Object that stores remote callbacks 
    for XML-RPC
    """
    def __init__(self, parent):
        self.parent=parent #parent is an appgui object
        self.state="InitialState"
        return
    
    def senddata(self, arguments):
        """
        This is named "senddata" but from our perspective it is really 
        "getdata".
        
        debugger_state is a tuple of:
        dname, regs, modules
        
        We return either a request for more information or not.
        """

        command = arguments[0]
        arguments= arguments[1]
        #devlog("vs", "Got Command: %s"%command)
        func=getattr(self,"c_%s"%command)
        if not func:
            #devlog("vs", "Command %s not found!"%command)
            return "Command %s not found!"%command
        ret=func(arguments)
        return ret
    
        
    def c_ssldata(self, arguments):
    
        payload=arguments[0] #first argument is our payload
        payload=base64.decodestring(payload)
        self.log(repr(payload))
        decodeddata=""
        if payload[:2]=="\x56\x02":
            #s:Envelope 
            #start of MC-NBFS for our sample data
            #in reality there's no way to know this, except to know the protocol you
            #are looking at...
            #what we have here is NBFS which is really NBFX
            decodeddata=parse_NBFS(payload)
            if decodeddata:    
                #now do our regular expression work
                for key in txtresdict:
                    print "Matching with regex %s"%key
                    p, replacewith = txtresdict[key]
                    result=p.search(decodeddata)
                    #if not result:
                    #    print "Did not match %s with data %s"%(key, decodeddata)
                    if result:
                        #print "Matched %s"%key
                        groupvalue=result.group(0)
                        if groupvalue:
                            print "Replacing %s with %s"%(repr(groupvalue), repr(replacewith))
                            decodeddata=decodeddata.replace(groupvalue,replacewith)
                            #ok, now we have new data, but we still have to put it in our string!
                            payload=replace_NBFS(payload, decodeddata)
                            if not payload:
                                #some fail in replace_NBFS
                                print "Failed to replace NBFS data!"
                                return ("LEAVEALONE", [])
                            #encode it for transmission - should not have to do this, but whateva'
                            payload=base64.encodestring(payload)
                            return ("REPLACE",[payload])
    
        #file("decodeddata.txt","ab").write("payload: %s\ndecodeddata=%s\n"%(payload, decodeddata))
 
        return ("LEAVEALONE", [])

    def log(self, msg):
        print msg 
        return 
    
class ssl_listener(object):
        def __init__(self):
                self.XMLRPCport=80
                return 
        
        def setupXMLRPCSocket(self):
                """
                Listen for XML-RPC requests on a socket
                """
                host="0.0.0.0"
                if self.XMLRPCport==0:
                        return 
                try:
                    server = SimpleXMLRPCServer.SimpleXMLRPCServer((host, self.XMLRPCport),allow_none=True)
                except TypeError:
                    print "2.4 Python did not allow allow_none=True!"
                    server = SimpleXMLRPCServer.SimpleXMLRPCServer((host, self.XMLRPCport))
                self.log("Set up XMLRPC Socket on %s port %d"%(host, self.XMLRPCport))
                listener_object=listener_instance(self)
                server.register_instance(listener_object)
                #start new thread.
                lt=listener_thread(server, listener_object)
                lt.start()
                self.listener_thread=lt 
                self.listener=listener_object
                return 
        
        def loop(self):
            while True:
                time.sleep(1)
            
        def log(self, msg):
            print msg 
            return
        
if __name__=="__main__":
        l=ssl_listener()
        l.XMLRPCport=int(sys.argv[1])
        l.setupXMLRPCSocket()
        l.loop()