#
# Registry Decoder
# Copyright (c) 2011 Digital Forensics Solutions, LLC
#
# Contact email:  registrydecoder@digitalforensicssolutions.com
#
# Authors:
# Andrew Case       - andrew@digitalforensicssolutions.com
# Lodovico Marziale - vico@digitalforensicssolutions.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#
from datastructures.strings.stringtable import *
from errorclasses import *

import common, datetime, binascii, struct
from string import ascii_uppercase, ascii_lowercase

# CODING CONVENTION:
# this class should ONLY have methods, no variables!
# all methods names must NOT start with __
# see attach_methods in template manager for details

class templateutil:


    def __init__(self, case_obj):
        self.o     = case_obj
        self.tree  = case_obj.tree

    def current_fileid(self):
        return [self.o.current_fileid]

    # returns the root path for the current tree
    # important since it changes between windows version
    def root_key(self):
        node = self.root_node()
        return self.key_name(node)


    def key_name(self, node):
        return self.tree.stringtable.idxtostr(node.sid)  
  
    # returns the path including the root key
    def get_path(self, path):
        return self.root_key() + path

    # returns the node at 'path'
    # None if path does not exists
    def root_path_node(self, path):
        if type(path) in [str,unicode]:
            path = path.split("\\")

        return self.tree.check_path_from_root(path, self.current_fileid())

    # returns True if the path exists starting from the root / False otherwise
    def path_exists(self, path):

        node = self.root_path_node(path)    

        if node:
            ret = True
        else:
            ret = False

        return ret

    # returns False if path has a name of 'namestr'
    # returns the list of names otherwise
    def get_name_data(self, path, namestr):

        ret = False
        
        path_list = path.split("\\")

        node = self.root_path_node(path_list)

        if node:
            ret = self.tree.obj.vtable.key_name(node[-1], namestr, self.current_fileid())
        
            if ret:
                ret = ret[0]

        return ret

    def get_value_for_node_name(self, node, namestr):

        ret = self.tree.obj.vtable.key_name(node, namestr, self.current_fileid())

        # skip the file id
        if ret:
            vals = ret[0]

            ret = self.stringid(vals.asciisid)
 
        return ret

    # like get_name_data but starts at 'node' instead of root
    def get_node_name_data(self, node, namestr):

        ret = self.tree.obj.vtable.key_name(node, namestr, self.current_fileid())

        # make it easier to handle None for plugins
        if not ret:
            ret = []
    
        return ret

    # returns if path has a name of 'namestr' with a value of 'valstr'
    # if it does then it returns the list of name value pairs       
    def get_value_data(self, path, namestr, valstr):

        ret = False
        
        path_list = path.split("\\") 
        node = self.root_path_node(path_list)

        #print "node: %s" % str(node)
        if node:
            ret = tree.obj.vtable.key_name_value(node[-1], namestr, valstr, self.current_fileid())
            # only one name expected
            if ret:
                ret = ret[0]

        return ret

    
    # same as get_value_data but starts at 'node' instead of the root
    def get_node_value_data(self, node, namestr, valstr): 

        ret = self.tree.obj.vtable.key_name_value(node, namestr, valstr, self.current_fileid())

        if ret:
            ret = ret[0]

        return ret


    # return a list of list of nodes for subkeys
    def path_subkeys(self, path):
       
        ret = []
        path_list = path.split("\\") 

        # get the first set of children
        subkeys = self.tree.walk_children_path(path_list, self.current_fileid(), 1)

        # enumerate to the keys so plugins don't have to
        # return list of lists of nodes
        if subkeys:
            for skey in subkeys:
                for n in skey:
                    node_list = skey[n]
                    for node in node_list:
                        ret.append(node)
                     
        return ret


    def get_last_write_time(self, node):
        
        unixtimestamp = node.timestamps[self.o.current_fileid]

        lastwrite = datetime.datetime.fromtimestamp(unixtimestamp).strftime('%Y/%m/%d %H:%M:%S UTC')

        return lastwrite
   
    '''
    WARNING
    All functions past this warning are meant only for advanced plugins or other registry decoder internal code
    These functions require direct interaction with registry decoder internal structures 
    '''
    # only meant for advanced plugins that deal directly with tree nodes
    def root_node(self):
        return self.tree.rootnode(self.current_fileid()[0])

    # gets the children (as nodes) of the specific node
    # depth determines how deep the child list will be
    def get_children_fid(self, node, depth=1):
        return self.tree.walk_children(node, self.current_fileid(), depth)

    def get_children(self, node, depth=1):
        
        cfid = self.get_children_fid(node, depth)
        ret  = None

        for cfi in cfid:
            ret = cfid[cfi]

        return ret

    def get_children_hash(self, node, depth=1):

        ret = {}
        children = self.get_children(node, depth)

        if not children:
            return ret

        for child in children:
            name = self.stringid(child.sid)

            ret[name] = child
            
        return ret

    def get_names_hash(self, node):

        ret  = {}

        vals = self.values_for_node(node)

        for val in vals:
            name  = self.stringid(val.namesid)
            value = self.stringid(val.asciisid)

            ret[name] = value
        
        return ret        

    def idxtonode(self, idx):
        return self.tree.idxtonode(idx)
    
    def values_for_node(self, node):
        return self.tree.obj.vtable.values_for_node(node, self.current_fileid())
    
    def stringid(self, sid):
        return self.tree.stringtable.idxtostr(sid)  

    # returns the nodes from 'node' to root of tree
    def node_to_root(self, node):
        nodes =  self.tree.walk_node_to_root(node)

        nodes.reverse()

        return nodes

    # returns the string path of 'node' to root of tree
    def path_node_to_root(self, node):

        nodes = self.tree.walk_node_to_root(node)
        path = []    

        for node in nodes:
            e = self.key_name(node)
            path.append(e)

        path.reverse()

        return "\\".join(path)
           
    def full_path_node_to_root(self, node):

        cur  = self.key_name(node)
        path = self.path_node_to_root(node) + "\\" + cur
        
        return path
 
    def node_searchfor(self, searchfor, partial=0):

        ret = []

        # returns a generator
        nodes = self.tree.node_searchfor(searchfor, self.current_fileid(), partial)

        for node in nodes:
            node.fullpath = self.full_path_node_to_root(node)
            ret.append(node)

        return ret

    def names_for_search(self, searchfor, partial):

        if partial:
            nodevals = self.tree.obj.vtable.names_for_search_partial(searchfor, self.current_fileid())
        else:
            nodevals = self.tree.obj.vtable.names_for_search(searchfor, self.current_fileid()) 
        
        self.process_nodevals(nodevals)

        return nodevals 

    def data_for_search(self, searchfor, partial):

        if partial:
            nodevals = self.tree.obj.vtable.data_for_search_partial(searchfor, self.current_fileid())
        else:
            nodevals = self.tree.obj.vtable.data_for_search(searchfor, self.current_fileid()) 
        
        self.process_nodevals(nodevals)

        return nodevals 

    def process_nodevals(self, nodevals):

        if not nodevals:
            return

        for nodeval in nodevals:
            
            nodeval.node          = self.tree.idxtonode(nodeval.nodeid)
            nodeval.node.fullpath = self.full_path_node_to_root(nodeval.node)

            nodeval.name     = self.stringid(nodeval.namesid)
            nodeval.data     = self.stringid(nodeval.asciisid)



################################################################################
################################################################################
############################# PUBLIC API #######################################
################################################################################
################################################################################


    # Return the string current control set (e.g. "001")
    def reg_get_currentcontrolset(self):

        return self.get_current_control_set()


    # Set headers for columns for report generated by this plugin.
    def reg_set_report_header(self, header):

        self.set_report_header(header)


    # Given a key path, returns the key object, else False.
    def reg_get_key(self, path):

        full_path = self.get_path(path)
        res = self.root_path_node(full_path)
        if res:
            return res[-1]
        else:
            return False			


    # Given a path, returns the key object, or raises an exception if the path
    # is not found. Use for plugins which should just fail if the given path is
    # not found.
    
    def reg_get_required_key(self, path):

        res = self.reg_get_key(path)

        if not res:
            raise RequiredKeyError(path) 

        return res


    # Given key object (above), return string key name.
    def reg_get_key_name(self, regkey):

        return self.key_name(regkey)        


    # Given a key object (above), returns the list of its sub-key objects.
    def reg_get_subkeys(self, regkey):
				
        subkeys = self.get_children(regkey)
        if subkeys:
            return subkeys
        else:
            return []
            

    # Given a key object (above), returns the list of its value objects.
    def reg_get_values(self, node):

        ret  = []
        vals = self.values_for_node(node)

        for val in vals:
            name  = self.stringid(val.namesid)
            value = self.stringid(val.asciisid)
            rawval = self.stringid(val.rawsid)
            ret.append((name, value, rawval))
					
        return ret

		
    # Given a value object (from list returned by reg_get_values), returns 
    # string name
    def reg_get_value_name(self, val):
        return val[0]

    # Given a value object (from list returned by reg_get_values), returns 
    # string data.
    def reg_get_value_data(self, val):
        return val[1]

    def reg_get_raw_value_data(self, val):
        raw = val[2]
        return binascii.unhexlify(raw)
    
    def reg_report(self, report_data):

        self.report(report_data)

    # Simplification function to report all value names and data for the given
    # key object.
    def reg_report_values_name_data(self, key):

        for val in self.reg_get_values(key):
            self.report((self.reg_get_value_name(val), self.reg_get_value_data(val)))


    # As above, but only reports values whose name / value pairs where name is
    # contained in name-list.
    def reg_report_values_name_data_filtered(self, key, name_list):
        
        for val in self.reg_get_values(key):
            if self.reg_get_val_name(val) in name_list:
                self.report((self.reg_get_value_name(val), self.reg_get_value_data(val)))


    # Sets the overall timestamp for the report generated by this plugin.
    def reg_set_report_timestamp(self, timestamp):
        self.set_timestamp(timestamp)


    # Takes key object, returns pretty formatted date string.
    def reg_get_lastwrite(self, key):
        return self.get_last_write_time(key)
        

    # Takes key object, returns dict { val_name : val_data }
    def reg_get_values_dict(self, key):
        pass


################################# SYSTEM ONLY ##################################

    # Returns the string current control set number, or raises an exception if
    # the current control set cannot be determined.

    def get_current_control_set(self):
	
        res = False	
        values = self.reg_get_values(self.reg_get_required_key("\Select"))
        for val in values:
            if self.reg_get_value_name(val) in ["Current", "current"]:
                return str(self.reg_get_value_data(val))


############################## UTILITY FUNCTIONS ###############################

    def pretty_unixtime(self, unixtime):
	
        if type(unixtime) != float:
            unixtime = float(unixtime)

        utc = datetime.datetime.utcfromtimestamp(unixtime)
        utcstr = utc.strftime("%Y/%m/%d %H:%M:%S.%f")

        return utcstr


    # Windows now has retarded 128-bit datetime objects. Here's how to parse them. 
    def pretty_date128(self, blob):
        
        # get every other byte
        
        res = struct.unpack("H"*8, blob)
        
        months = ("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec")
        days = ("Sun","Mon","Tue","Wed","Thu","Fri","Sat")
        yr,mon,dow,dom,hr,minute,sec,ms = res
        if (hr < 10):
            hr = "0" + str(hr) 
        if (minute < 10):
            minute = "0" + str(minute) 
        if (sec < 10):
            sec = "0" + str(sec) 
        date_string = "%s %s %s, %s:%s:%s %s" % (days[dow], months[mon - 1], dom, hr, minute, sec, yr)
        
        return date_string


    def rot13(self, data):
        """ A simple rot-13 encoder since `str.encode('rot13')` was removed from
            Python as of version 3.0.  It rotates both uppercase and lowercase letters individually.
        """
        total = []
        for char in data:
            if char in ascii_uppercase:
                index = (ascii_uppercase.find(char) + 13) % 26
                total.append(ascii_uppercase[index])
            elif char in ascii_lowercase:
                index = (ascii_lowercase.find(char) + 13) % 26
                total.append(ascii_lowercase[index])
            else:
                total.append(char)
        return "".join(total)
        
