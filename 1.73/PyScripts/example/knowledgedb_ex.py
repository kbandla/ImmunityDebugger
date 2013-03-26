#!/usr/bin/env python
"""
Example of using the knowledge methods

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__ = '1.0'

import immlib
from immutils import *


"""
Log output for this example:

Saved Object: NOCRASH
Saved Object: sample_object
Got from knowledge database: {'EAX' = 0, 'EBX' = -1, 'ESP': 1226236}
Removed NOCRASH from knowledge database
"""

def main(): 
    imm = immlib.Debugger()
    
    #adding objects
    object1={"EAX":0x00000000,"EBX":-1,"ESP":0x0012B5FC}
    imm.addKnowledge("NOCRASH",object1)
    
    object2=["just","a","sample"]
    imm.addKnowledge("sample_object",object2)

    #listing objects
    knowledge_db=imm.listKnowledge()
    for object in knowledge_db:
        imm.Log("Saved Object: %s" %str(object))
        
    
    #getting objects
    object_id="NOCRASH"
    sObject=imm.getKnowledge(object_id)
    imm.Log("Got from knowledge database: %s" %str(sObject))
    
    #forgetting object
    imm.forgetKnowledge(object_id)
    imm.Log("Removed %s from knowledge database" %object_id)
    
if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"    
    