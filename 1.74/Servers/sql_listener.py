#!/usr/bin/env python
"""
SQL Listener - for sqlhooker.py client-side
"""
import sys
from threading import Thread
import time


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
    
    def sendsql(self, arguments):
        """
        This is named "sendstate" but from our perspective it is really 
        "getstate".
        
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
        #After I return this, I need to sleep a couple seconds to 
        #give the process time to restart, and then resend our attack
        return ret
    
        
    def c_sqlquery(self, arguments):
    
        sql_query=arguments[0] #first argument is sql query
        self.log(sql_query)
        return ("Thanks", [])

    def log(self, msg):
        print msg 
        return 
    
class sql_listener(object):
        def __init__(self):
                self.XMLRPCport=80
                return 
        
        def setupXMLRPCSocket(self):
                """
                Listen for XML-RPC requests on a socket
                """
                import SimpleXMLRPCServer
                import threading
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
        l=sql_listener()
        l.XMLRPCport=int(sys.argv[1])
        l.setupXMLRPCSocket()
        l.loop()