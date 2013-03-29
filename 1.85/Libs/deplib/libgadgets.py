"""
This library has two main uses:
- To create and populate a gadget's database (mainly using the function add_module_entry.
- To retrieve a specific gadget from a database, either by hash searching or by property searching.

To do a hash-search you need the output of hashState() from a StateMachine class instance, so the typical 
usemode is to use an empty (just instantiated) StateMachine instance to model your gadget needs (like setting a register or whatever)
and using it to calculate the hashes for the search.
It also needs a cache of hashes, so that we dont search for the same hashes twice, this is accomplished by instantiating a 
HashesDictionary class.
Using this two arguments, you can execute search_by_hashes(), which is a generator that returns a 3-tuple (module_id, offset, complexity) 
for each gadget it founds that meets the given requirements.

A properties-search is quite similar to this, but it might be executed without a StateMachine instance, using the translate_properties function.
If you decide to use a StateMachine instance, you just need to execute calcProperties() and use the output dictionary to feed the search_by_properties function.
As in the hash-search case, you need an instance of a properties cache, called PropertiesDictionary.
A search by properties, means you dont get an exact match of what you need, but you actually search by asking what registers or flags affects a given register.
Or what memory (actually what memory indexes) affects a given register. This kind of search is specially useful for pivot stack searching, as you want to use
*any* gadget that makes ESP/EIP points to where you need, no matter how.

"""

from x86smt.sequenceanalyzer import SequenceAnalyzer
import operations
import time
import cPickle
from datetime import timedelta

class GadgetsDB:
    def __init__(self, imm, dbtype=None, dbname=None, host=None, username="", passwd="", quiet=False):
        if not dbtype: dbtype="sqlite3"
        if not dbname:
            if dbtype == "sqlite3":
                dbname="gadgets.sq3"
            else:
                dbname="gadgets"
        if not host: host="127.0.0.1"
        if not username: username=""
        if not passwd: passwd=""
        
        self.imm                 = imm
        self.database_type       = dbtype
        self.database_file       = dbname          #SQLite3 support
        self.database_user       = username        #MYSQL support
        self.database_passwd     = passwd
        self.database_host       = host
        self.database_db         = dbname
        self.db_connection       = None
        self.debug               = False
        self.force_analysis      = False
        self.quiet               = quiet
        self.db_package          = None
        self.max_gadgets         = None
        
        ret=self.database_connect()
        if not ret:
            if not self.quiet: self.imm.log("[!] Could not connect to the database!")
        
        # Create the database if it doesn't exist
        db_cursor=self.db_connection.cursor()
        if self.database_type == "sqlite3":
            try:
                db_cursor.execute("SELECT 1 from modules")
            except self.db_package.OperationalError:
                if not self.quiet: self.imm.log("[*] Initializing Database %s"%self.database_file)
                self.initialize_database()
            else:
                if not self.quiet: self.imm.log("[*] Database file already exists: %s"%self.database_file)
        elif self.database_type == "mysql":
            if db_cursor.execute("SHOW TABLES") == 0:
                if not self.quiet: self.imm.log("[*] Initializing Database")
                self.initialize_database()
            else:
                if not self.quiet: self.imm.log("[*] Database %s already exists"%self.database_db)
        else:
            db_cursor.close()
            raise Error, "DB type not defined"
        db_cursor.close()
        
        #initialize objects
        self.instance = searchOpcodesRETN(self.imm, filter_jumps=True, filter_calls=True)
    
    ######### basic DB handling #######
    
    def database_connect( self ):
        if self.database_type == "mysql":
            try:
                self.db_package=__import__("MySQLdb", globals(), locals(), "*")
            except:
                self.imm.log("MySQLdb was not found, you need to install mysql-python")
                return False
        elif self.database_type == "sqlite3":
            self.db_package=__import__("sqlite3", globals(), locals(), "*")
        
        if self.database_type == "sqlite3":
            self.db_connection = self.db_package.connect( self.database_file, 90 ) #90 => lock timeout
        elif self.database_type == "mysql":
            self.db_connection = self.db_package.connect( host=self.database_host, user=self.database_user, passwd=self.database_passwd, db=self.database_db )
        else:
            return False
        
        if self.db_connection:
            if self.database_type == "sqlite3":
                if not self.quiet: self.imm.log("[*] Connected to DB: %s"%self.database_file)
            else:
                if not self.quiet: self.imm.log("[*] Connected to DB: %s (user=%s, host=%s)"%(self.database_db, self.database_user, self.database_host))
            return True
        
        if self.database_type == "sqlite3":
            if not self.quiet: self.imm.log("[*] Error connecting to database %s" % self.database_file )
        else:
            if not self.quiet: self.imm.log("[*] Error connecting to database %s (user=%s, host=%s)"%(self.database_db, self.database_user, self.database_host))
        return False 
    
    def initialize_database( self ):
        """
        the default definitions are for SQLite3
        """
        
        if not self.quiet: self.imm.log("[!] Creating Database")
        
        db_cursor=self.db_connection.cursor()
        
        # Create the primary database and general purpose tables
        modules="CREATE TABLE modules (module_id INTEGER PRIMARY KEY AUTOINCREMENT, module_name TEXT, module_version TEXT, base_address INTEGER)"
        if self.database_type == "mysql":
            modules=modules.replace("AUTOINCREMENT","AUTO_INCREMENT")
        db_cursor.execute(modules)
        
        #create tables related to DEPlib
        gadgets="""CREATE TABLE gadgets (module_id INTEGER, offset INTEGER, dump BLOB, complexity INTEGER, PRIMARY KEY (module_id, offset))"""
        db_cursor.execute(gadgets)
        
        #for SAT searching we will use something like: all gadgets in <list_of_modules> that have <property> ordered by complexity
        #dump here is a pickled version of a set() of 2-tuples (complexity, offset) that have a given value
        for r in ["EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP", "FLAGS"]:
            db_cursor.execute("""CREATE TABLE %sprops (module_id INTEGER, value INTEGER, dump BLOB)"""%r)
            db_cursor.execute("""CREATE INDEX %sprops_value_idx ON %sprops (module_id, value)"""%(r,r))
        
        #for hash searching, we will use: <dump> where module_id=N and hash=M
        db_cursor.execute("""CREATE TABLE hashes (module_id INTEGER, hash TEXT, dump BLOB)""")
        db_cursor.execute("""CREATE INDEX module_hash_idx ON hashes (module_id, hash)""")
        
        #stats (time is in seconds)
        db_cursor.execute("""CREATE TABLE stats (module_id INTEGER, gadgets_count INTEGER, time INTEGER)""")
        
        # Save our database updates
        self.db_connection.commit()
        db_cursor.close()
    
    ######## DB inserts #########
    
    def all_module_scan( self ):
        modules = self.imm.getAllModules()

        for module in modules.keys():
            self.add_module_entry(modules[module])
    
    def add_module_entry( self, module ):
        """
        Add a module to the database, given a module instance.
        
        """
        
        module_name=module.getName()
        module_version=module.getVersion().split("(")[0].strip()
        module_address=module.getBaseAddress()
        db_cursor=self.db_connection.cursor()
        
        query="SELECT module_id FROM modules WHERE module_name = ? and module_version = ?"
        if self.database_type == "mysql": query=query.replace("?","%s")
        db_cursor.execute(query, (module_name, module_version))
        response = db_cursor.fetchone()

        if response and self.force_analysis:
            #delete any previous analysis and do all over again
            db_cursor.execute("DELETE FROM modules WHERE module_id = %d"%response[0])
            db_cursor.execute("DELETE FROM gadgets WHERE module_id = %d"%response[0])
            db_cursor.execute("DELETE FROM hashes WHERE module_id = %d"%response[0])
            self.db_connection.commit()
            response=False
        
        if not response:
            insert_query = ( module_name, module_version, module_address, )
            
            query="INSERT INTO modules (module_name, module_version, base_address) VALUES (?, ?, ?)"
            if self.database_type == "mysql": query=query.replace("?","%s")
            db_cursor.execute(query, insert_query)
            self.db_connection.commit()
            
            module_id = db_cursor.lastrowid
            if not self.quiet: self.imm.log("[*] Storing new module: %s (%s) in the database (module_id=%d)." % ( module_name, module_version, module_id ) )
            
            start=time.time()
            count=self.add_gadgets(module_name, module_id, module_address)
            query="INSERT INTO stats (module_id, gadgets_count, time) VALUES (?, ?, ?)"
            if self.database_type == "mysql": query=query.replace("?","%s")
            db_cursor.execute(query, (module_id, count, int(time.time() - start)))
            self.db_connection.commit()
            if not self.quiet: self.imm.log("[*] Module %s DONE! in %s, %d gadgets processed."%(module_name, str(timedelta(seconds=(time.time() - start))), count))
        else:
            if not self.quiet: self.imm.log("[*] Module %s (%s) already present in the database. Skipping..." % ( module_name, module_version) )
        
        db_cursor.close()
        return
    
    def add_gadgets(self, module_name, module_id, module_address):
        hashes = {}
        props = {}
        
        c=0
        for r in self.instance.search(module_name):
            if self.max_gadgets and c >= self.max_gadgets:
                if self.debug:
                    self.imm.log("[*] Max gadgets count reached (%d)"%self.max_gadgets)
                break
            
            sa = SequenceAnalyzer(self.imm)
            
            #consider direction flag off, which is true 99.9% of the time and improves speed over 9000 times
            sa.state.flags["_DF"]=sa.state.solver.false
            addr = r[0]
            
            if self.debug:
                self.imm.log("[*] Analyzing gadget at 0x%08x"%addr, addr)
            
            if not sa.analyze(addr, depth=r[1], stopEIP=r[0]+r[2]):  #if the sequence analyzer failed, we cant use this gadget
                if not self.quiet: self.imm.log("[!] Sequence Analyzer failed for gadget 0x%x"%addr, addr)
                continue
            
            c+=1
            addr -= module_address #store offset, not address
            
            (regProps, flagProps)=sa.state.calcProperties()
            complexity=sa.state.calcComplexity(regProps, flagProps)
            
            for k,v in sa.state.hashState().iteritems():
                key=(k,v)
                if not hashes.has_key(key):
                    hashes[key]=set()
                hashes[key].add((complexity, addr))
            
            for k,v in regProps.iteritems():
                if not v:
                    continue
                key=(k,v)
                if not props.has_key(key):
                    props[key]=set()
                props[key].add((complexity, addr))
            
            if flagProps:
                key=("FLAGS",flagProps)
                if not props.has_key(key):
                    props[key]=set()
                props[key].add((complexity, addr))
            
            self.add_gadget_entry(addr, sa.state, complexity, module_id)
            self.db_connection.commit()
            del sa
        
        self.add_hashes(module_id, hashes)
        self.add_props(module_id, props)
        self.db_connection.commit()
        
        return c
    
    def add_gadget_entry( self, addr, state, complexity, module_id ):
        if self.debug:
            self.imm.log("[*] Adding gadget at module offset 0x%08x"%addr)

        query = ( module_id, addr, self.db_package.Binary(cPickle.dumps(state, cPickle.HIGHEST_PROTOCOL)), complexity )
        
        sql="""INSERT INTO gadgets ( module_id, offset, dump, complexity ) VALUES (?, ?, ?, ?)"""
        if self.database_type == "mysql": sql=sql.replace("?","%s")
        db_cursor=self.db_connection.cursor()
        db_cursor.execute(sql, tuple(query))
        db_cursor.close()
        
        return

    def add_hashes( self, module_id, hashes ):
        if self.debug:
            self.imm.log("[*] Adding hashes for module id=%d"%module_id)

        db_cursor=self.db_connection.cursor()
        for k,v in hashes.iteritems():
            insert_query = ( module_id, "%s%08X"%(k[0],k[1]), self.db_package.Binary(cPickle.dumps(v, cPickle.HIGHEST_PROTOCOL)) )
            
            query="""INSERT INTO hashes ( module_id, hash, dump ) VALUES (?, ?, ?)"""
            if self.database_type == "mysql": query=query.replace("?","%s")
            db_cursor.execute(query, insert_query)
            
        db_cursor.close()
        
        return
    
    def add_props( self, module_id, props ):
        if self.debug:
            self.imm.log("[*] Adding props for module id=%d"%module_id)

        db_cursor=self.db_connection.cursor()
        for k,v in props.iteritems():
            insert_query = ( module_id, k[1], self.db_package.Binary(cPickle.dumps(v, cPickle.HIGHEST_PROTOCOL)) )
            
            query="""INSERT INTO %sprops ( module_id, value, dump ) VALUES (?, ?, ?)"""%k[0]
            if self.database_type == "mysql": query=query.replace("?","%s")
            db_cursor.execute(query, insert_query)
            
        db_cursor.close()
        
        return
    
    ######################## Utils
    
    def list_modules(self):
        self.imm.log("Listing all modules available...")
        self.imm.log("---------------------------------------------------------------------------------------------------")
        self.imm.log("|Module ID|Module Name     |Module Version     |Base Address|Gadget's Count|Enlapsed Analysis Time|")
        self.imm.log("---------------------------------------------------------------------------------------------------")
        query="SELECT modules.module_id, module_name, module_version, base_address, gadgets_count, time FROM modules LEFT JOIN stats USING (module_id) ORDER BY module_id"
        db_cursor=self.db_connection.cursor()
        db_cursor.execute(query, ())
        for row in db_cursor.fetchall():
            self.imm.log("|%9d|%16s|%19s|    %08X|%14d|%22s|"%(row[0],row[1],row[2],row[3],row[4], str(timedelta(seconds=row[5]))))
        self.imm.log("---------------------------------------------------------------------------------------------------")
        db_cursor.close()
    
    def get_all_module_ids(self):
        ret=[]
        db_cursor=self.db_connection.cursor()
        query="SELECT module_id FROM modules"
        db_cursor.execute(query, ())
        
        for row in db_cursor.fetchall():
            ret.append(row[0])
        
        db_cursor.close()
        return ret
        
    def get_module_ids(self, modules):
        """
        Modules is a list of either: 
          - 2-tuples, each one have a module_name and module_version
          - module_name string or 1-tuple with module_name
          - module_id
        
        Returns a list of module IDs.
        """
        
        ret = []
        db_cursor=self.db_connection.cursor()
        
        if not isinstance(modules, list) and not isinstance(modules, tuple):
            modules=[modules]
                
        for mod in modules:
            if isinstance(mod, int) or isinstance(mod, long):
                ret.append(mod)
            elif not isinstance(mod, str) and len(mod) > 1:
                query="SELECT module_id FROM modules WHERE LOWER(module_name) = LOWER(?) and LOWER(module_version) = LOWER(?)"
                if self.database_type == "mysql": query=query.replace("?","%s")
                db_cursor.execute(query, (mod[0], mod[1]))
                tmp = db_cursor.fetchone()
                if tmp != None:
                    ret.append(tmp[0])
            else:
                if not isinstance(mod, str):
                    mod=mod[0]
                query="SELECT module_id FROM modules WHERE LOWER(module_name) = LOWER(?)"
                if self.database_type == "mysql": query=query.replace("?","%s")
                db_cursor.execute(query, (mod, ))
                for row in db_cursor.fetchall():
                    ret.append(row[0])
        
        db_cursor.close()
        return ret
    
    def get_module_base_from_id(self, moduleids):
        """
        Returns a dictionary where the module_id is key and base_address is value.
        
        """
        
        ret = {}
        db_cursor=self.db_connection.cursor()
        for id in moduleids:
            query="SELECT base_address FROM modules WHERE module_id = ?"
            if self.database_type == "mysql": query=query.replace("?","%s")
            db_cursor.execute(query, (id, ))
            tmp = db_cursor.fetchone()
            if tmp != None:
                ret[int(id)]=tmp[0]
        
        db_cursor.close()
        return ret
    
    def get_addresses(self, module_id, hashkey):
        """
        hashkey is a 2-tuple (reg/mem/flags key, hashvalue).
        
        return a set() of 2-tuples: (complexity, address) for a given moduleid and hash.
        """

        ret=None
        db_cursor=self.db_connection.cursor()
        query="SELECT dump FROM hashes WHERE module_id = ? and hash = ?"
        if self.database_type == "mysql": query=query.replace("?","%s")
        db_cursor.execute(query, (module_id, "%s%08X"%(hashkey[0],hashkey[1])))
        
        tmp=db_cursor.fetchone()
        if tmp != None:
            ret =  cPickle.loads(str(tmp[0]))
        
        db_cursor.close()
        return ret
    
    def get_addresses_by_props(self, module_id, propkey):
        """
        propkey is a 2-tuple (reg/flags key, propvalue).
        
        If key == FLAGS, propvalue can also be a 2-tuple (mask, value)
        
        return a set() of 2-tuples: (complexity, address) for a given moduleid and prop.
        """

        ret=None
        db_cursor=self.db_connection.cursor()
        if propkey[0] == "FLAGS" and (isinstance(propkey[1], tuple) or isinstance(propkey[1], list)):
            query="SELECT dump FROM FLAGSprops WHERE module_id = %d and value & %d = %d"%(module_id, propkey[1][0], propkey[1][1])
        else:
            query="SELECT dump FROM %sprops WHERE module_id = %d and value = %d"%(propkey[0], module_id, propkey[1])
        db_cursor.execute(query, ())
        
        tmp=db_cursor.fetchone()
        if tmp != None:
            ret =  cPickle.loads(str(tmp[0]))
        
        db_cursor.close()
        return ret
    
    def get_gadget_by_offset(self, module_id, offset):
        """
        For hash-based searching
        """
        
        ret=None
        db_cursor=self.db_connection.cursor()
        query="SELECT dump FROM gadgets WHERE module_id = ? AND offset = ?"
        if self.database_type == "mysql": query=query.replace("?","%s")
        db_cursor.execute(query, (module_id, offset))
        
        tmp = db_cursor.fetchone()
        if tmp != None:
            ret = cPickle.loads(str(tmp[0]))
        
        db_cursor.close()
        return ret
    
    def translate_properties(self, regs=None, flags=None):
        """
        regs is a dictionary with registers as key and a 2-tuple (affected-by-regs-list, mem-indexes-list) as value:
          - 
            * affected-by-reg is a list of regs or the word "FLAGS" or the word "CONST" for cases where it is modified only by a constant value
            * mem-indexes is a list of regs, the word "FLAGS" or the word "CONST" for independant constant indexes (this last one is exclusive)
          Note: any non-present register means it's not important for the search
        
        flags is a dictionary with flags as key (one letter for each flags, like here: "CPAZSDO"), and as values one of this:
          - True: must be modified
          - False: must not be modified
          - None (or not present): we dont care about this flag
        
        ex: {"ESP":"EAX", "EIP":((), "EAX")}, can be used to find a stack-pivot from EAX.
        
        The returned dictionary can be used directly for gadget's searching by property (GadgetDB.search_by_properties)
        """
        
        ret={}
        order=["EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP", "FLAGS"]
        f_order="CPAZSDO"
        
        if regs:
            for r,v in regs.iteritems():
                val=1        #modified
                
                if isinstance(v, str):
                    v=[[v]]
                
                v=list(v)
                if isinstance(v[0], str):
                    v[0]=[v[0]]
                
                if len(v) > 1 and isinstance(v[1], str):
                    v[1]=[v[1]]
                
                for aff in v[0]:
                    if aff == "CONST":
                        break
                    idx=order.index(aff.upper())
                    val|=1 << idx + 1
                
                if len(v) > 1:
                    if v[1][0] == "CONST":
                        val|=1 << 1+9+1+9+1
                    else:
                        for aff in v[1]:
                            idx=order.index(aff.upper())
                            val|=1 << idx + 1+9+1
    
                ret[r.upper()]=val
        
        if flags:
            val=0
            mask=0
            for f,v in flags.iteritems():
                idx=f_order.index(f.upper())
                if v == True:
                    val|=1 << idx
                    mask|=1 << idx
                elif v == False:
                    mask|=1 << idx
            
            ret["FLAGS"]=(mask, val)
        
        return ret
  
    def search_by_properties(self, props, propsDictionary):
        """
        For SAT searching. props is a dictionary with p_* keys and the wanted prop value as value.
        If the prop is FLAGS, value is a 2-tuple (mask, value).
        
        This function is a generator that returns a 3-tuple (modid, offset, complexity) ordered by complexity, each time is run.
        """
        
        for modid in propsDictionary.module:
            addresses=None
            for propkey in props.iteritems():
                tmp = propsDictionary[modid][propkey]
                if not tmp:
                    addresses=None
                    break
                
                if not addresses:
                    addresses=tmp
                else:
                    addresses=addresses.intersection(tmp)
                
                if not addresses:
                    break
            
            if addresses:
                addresses=list(addresses)
                addresses.sort()
                for addr in addresses:
                    yield (modid, addr[1], addr[0])
    
    def search_by_hashes(self, searchHashes, hashesDictionary):
        """
        searchHashes is the output from sa.hashState().
        hashesDictionary is an instance of HashesDictionary.
        
        This function is a generator that returns a 3-tuple (modid, offset, complexity) ordered by complexity, each time is run.
        """
        
        for modid in hashesDictionary.module:
            addresses=None
            for hashkey in searchHashes.iteritems():
                tmp = hashesDictionary[modid][hashkey]
                if not tmp:
                    addresses=None
                    break
                
                if not addresses:
                    addresses=tmp
                else:
                    addresses=addresses.intersection(tmp)
                
                if not addresses:
                    break
            
            if addresses:
                addresses=list(addresses)
                addresses.sort()
                for addr in addresses:
                    yield (modid, addr[1], addr[0])


class HashesDictionary(dict):
    """
    This class retrieves a set of 2-tuples (complexity, gadget-address) from the GadgetsDB, given a certain module_id and a hash 2-tuple.
    If only a hash is provided, it returns a tuple following the original moduleids order with the results for each module.
    
    modules is a list of module_id.
    
    ex:
    hashes=HashesDictionary(gdb, [1,2,3])
    
    addresses=hashes[("EAX","12345678")] (queries all modules)
    other=hashes[1][("MEM12345678","9ABCDEF0")] (queries only module 1)
    """
    
    def __init__(self, gdb, modules):
        self.gdb=gdb
        
        if isinstance(modules, list):
            modules=tuple(modules)
        
        if isinstance(modules, tuple):
            for mod in modules:
                dict.__setitem__(self, mod, HashesDictionary(self.gdb, mod))
        
        self.module=modules
        
    def __getitem__(self, hashkey):
        #child dictionaries
        if isinstance(hashkey, int) or isinstance(hashkey, long):
            return dict.__getitem__(self, hashkey)
        
        if isinstance(hashkey, list):
            hashkey=tuple(hashkey)
            
        if not isinstance(hashkey, tuple):
            raise TypeError
        
        if dict.has_key(self, hashkey):
            return dict.__getitem__(self, hashkey)
        else:
            if isinstance(self.module, tuple):
                #we are the parent class, so we return a sorted tuple following the original module_id order.
                ret=[]
                for mod in self.module:
                    tmpdict=dict.__getitem__(self, mod)
                    tmp = tmpdict[hashkey]
                    ret.append(tmp)
                ret=tuple(ret)
                dict.__setitem__(self, hashkey, ret)
                return ret
            else:
                #we are a child instance, get the information from the DB
                tmp=self.gdb.get_addresses(self.module, hashkey)
                dict.__setitem__(self, hashkey, tmp)
                return tmp

class PropertiesDictionary(dict):
    """
    This class retrieves a set of 2-tuples (complexity, gadget-address) from the GadgetsDB, given a certain module_id and a property 2-tuple.
    If only a property is provided, it returns a tuple following the original moduleids order with the results for each module.
    
    If the register in the property 2-tuple is FLAGS you can provide either the actual value you want to fetch or a 2-tuple (mask, value) if you only care about some flag
    
    modules is a list of module_id.
    
    ex:
    props=PropertiesDictionary(gdb, [1,2,3])
    
    addresses=props[("EAX",3)] (queries all modules)
    other=hashes[1][("FLAGS",7)] (queries only module 1)
    """
    
    def __init__(self, gdb, modules):
        self.gdb=gdb
        
        if isinstance(modules, list):
            modules=tuple(modules)
        
        if isinstance(modules, tuple):
            for mod in modules:
                dict.__setitem__(self, mod, PropertiesDictionary(self.gdb, mod))
        
        self.module=modules
        
    def __getitem__(self, propkey):
        #child dictionaries
        if isinstance(propkey, int) or isinstance(propkey, long):
            return dict.__getitem__(self, propkey)
        
        if isinstance(propkey, list):
            propkey=tuple(propkey)
            
        if not isinstance(propkey, tuple):
            raise TypeError
        
        if dict.has_key(self, propkey):
            return dict.__getitem__(self, propkey)
        else:
            if isinstance(self.module, tuple):
                #we are the parent class, so we return a sorted tuple following the original module_id order.
                ret=[]
                for mod in self.module:
                    tmpdict=dict.__getitem__(self, mod)
                    tmp = tmpdict[hashkey]
                    ret.append(tmp)
                ret=tuple(ret)
                dict.__setitem__(self, propkey, ret)
                return ret
            else:
                #we are a child instance, get the information from the DB
                tmp=self.gdb.get_addresses_by_props(self.module, propkey)
                dict.__setitem__(self, propkey, tmp)
                return tmp

class searchOpcodesRETN:
    """
    searchOpcodesRETN.search returns a list of gadgets along with their length in instructions & length in bytes
    e.g., (77fea29c,6, 9), (77fea299, 7, 12)
    """
    
    def __init__(self, imm, filter_calls=False, filter_jumps=False):
        self.imm = imm
        self.maxbackward = 20 #max instructions backward

        self.filter_calls = filter_calls
        self.filter_jumps = filter_jumps
        
    def search(self, module):
        """
        module is the page owner's name
        
        Returns a list where each member is a RETN ended routine.
        For each RETN found, return a list with all the possible ways to disasm backward this routine.
        Each possible disasm is a list of opcode instances (backward ordered)
        """
        self.imm.log('Starting gadget search in %s'%module)
        retns = []
        
        #we search only in memory pages that are executables and part of a specific module
        for mem in self.imm.getMemoryPageByOwner( module ):
            if "EXECUTE" in mem.getAccess(human=1):
                retns += mem.search("\xC3")    #RETN
                retns += mem.search("\xC2")    #RETN ##
        
        retns.sort()
        for retn in retns:
            for e in range(0, self.maxbackward*20): #an x86 instruction must be <= 20bytes long
                decoded = self.gadgetCandidate(retn-e, e)
                #we didn't find any way to decode this routine
                if not decoded:
                    continue
                yield (retn - e, decoded, e)
    
    def gadgetCandidate(self, addr, length):
        """returns True or False as to whether the length bytes starting at addr
        decode to a gadget that ends in ret or ret xx.  No analysis is done.
        """
        e=0
        num=0
        retoffset=0
        foundret = False
        while (e<=length):
            op = operations.operation(self.imm.disasmFile(addr+e))
            if not op.validateInstruction():
                break

            if self.filter_calls and op.isCall():
                break
            if self.filter_jumps and (op.isJmp() or \
                                      op.isConditionalJmp()):
                break
            
            opsize = op.getOpSize()
            num += 1
            if num > self.maxbackward: #stop here
                return 0
            
            if op.isRet():
                retoffset = op.op1Constant()
                #ignore stupidly large ESP moves and RETNs that are not the one we want
                if retoffset > 0x100 or e!= length:
                    foundret = False
                else:
                    foundret = True
                break #we might find a RETN while disasm backward that's not the RETN we were expecting, 
                      #but it cuts our gadget anyway
                    #self.imm.log('%x, %d bytes til return'%(addr,e+opsize))
            e += opsize
        if not foundret:
            num = 0
        return num
