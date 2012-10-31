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
import sys

from registrydecoder.errorclasses import *

class ptree:

    def __init__(self, obj):
        self.obj      = obj
        
        self.nodehash    = {}
        self.startidx    = 0
        self.stringtable = obj.stringtable
        self.rootnodes   = {}

        self.before_pickle()

    # windows time to unixtime             
    def convert_timestamp(self, element):

        l = long(element.timestamp_low)
        h = long(element.timestamp_high)
        t = float(h) * 2**32 + l
        unixtime = t * 1e-7 - 11644473600

        return unixtime

    # returns the node at 'idx'
    def idxtonode(self, idx):
        
        nidx = "%d" % idx

        try:
            ret = self.nodehash[nidx]
        except:
            ret = None
    
        return ret        

    def parent_id(self, parent):

        # for the root node    
        if not parent:
            pid = -1
        else:
            pid = parent.nodeid

        return pid

    def rootnode(self, fileid):
       
        ret = self.rootnodes[fileid]
        return ret 

    # reset values that could take up memory
    # and that aren't neded after processing
    def before_pickle(self):
        self.past_queries = {}
            
    # add node to hash tabe
    def add_hash(self, node):

        intid = len(self.nodehash) + self.startidx

        newid = intid + 1

        key = "%d" % newid
        
        self.nodehash[key] = node

        return newid

    # adds a node to the hash table
    def add_node(self, node):

        nid = self.add_hash(node)
        node.nodeid = nid

    def child_of_parent(self, parent, sid):

        pid = self.parent_id(parent)

        hkey = "%d|%d" % (pid, sid)

        if hkey in self.past_queries:
            ret = self.past_queries[hkey]
        else:
            ret = None
        
        return ret
        
    def get_converted(self, asciidata):
    
        atype = type(asciidata)

        if atype == list:
            asciidata = ",".join([x for x in asciidata]) 
            
        elif atype == bytearray:
            asciidata = asciidata.decode("utf-16", "replace")

        elif atype == str:
            asciidata = asciidata.decode("utf-8", "replace")
            
        elif atype == int:
            asciidata = "%d" % asciidata

        elif atype == long:
            asciidata = "%ld" % asciidata

        elif atype == unicode:
            pass
 
        else:
            print "Unknown type: %s | %s" % (atype,asciidata)
            
        return asciidata

    # path is the full path of whatever is being put into the tree
    # checks if each key is in the tree, if not adds it
    def create_strings(self, fileid, element, isroot):

        parent = None

        timestamp = element.timestamp

        firstnode = 1

        # create for all strings that don't exist
        for curkey in element.path:
                     
            curkey = self.get_converted(curkey)
            
            sid  = self.obj.stringtable.getadd_string(curkey)
            node = self.child_of_parent(parent, sid)

            # add a new node
            if not node:
                node = nodeobj(fileid=fileid, sid=sid)
                # assigns node id
                self.add_node(node)
        
                node.parent = parent
    
                pid = self.parent_id(parent)

                # unique
                hkey = "%d|%d" % (pid, sid)
                self.past_queries[hkey] = node    
                            
            # update fileid
            elif not fileid in node.fileids: # and idx < max:
                node.fileids.append(fileid)
            
            parent  = node
            
            if firstnode:        
                self.rootnodes[fileid] = node
                firstnode = 0
    
        if node:
            # take the final value_list
            node.valuelist = element.value_list
            
            if not hasattr(node, "values"):
                node.values = {}

            self.obj.vtable.create_values(node, fileid)

            del node.valuelist
        
            node.timestamps[fileid] = timestamp
        
    def add_path(self, fileid, registry_path, isroot):
        
        self.create_strings(fileid, registry_path, isroot)

#
# the rest are functions that operate on a case's tree
#
    def query_results(self):
        
        ret = self.db.cursor.fetchone()

        if ret:
            ret = ret[0]

        return ret

    def query_results_all(self):

        ret = self.db.cursor.fetchall()

        return ret

    def check_fileids(self, node, good_fileids):

        # not a node for the root
        if good_fileids[0] == -1 or node is None:
            goodids = [-1]
        else:
            goodids = list(set(good_fileids) & set(node.fileids))

        return goodids

    # checks if a path exists starting at node
    # returns lists of nodes if found
    def check_path_node(self, path, node, fileids):
        
        ret = []
        
        # walk each part of path
        for p in path:
            good = 0
                
            if self.check_fileids(node, fileids):
        
                pid = self.parent_id(node)

                # string of current path element
                sid = self.stringtable.string_id(p)

                # if the string exists...
                if sid:
                    # find the node with this string and parent of 'pid'
                    self.db.cursor.execute("select nodeid from treenodes where stringid=? and parentid=?",(sid,pid))
                    nodeid = self.query_results()

                    if nodeid:
                        node = self.idxtonode(nodeid)
                        
                        # recheck in case this is the last part of the path
                        if self.check_fileids(node, fileids):

                            ret.append(node)
                            good = 1

            else:
                print "%s doesnt pass the file id test" % p

            if good == 0:
                ret = []
                break

        return ret

    
    # checks if a path exists starting at the root
    #ret  =    obj.tree.check_path_from_root(["Clients","Contacts","Address Book"],[-1])
    def check_path_from_root(self, path, fileids):

        return self.check_path_node(path, None, fileids)
    
    def walk_node_to_root(self, node):
    
        ret = []

        self.do_walk_to_root(node, ret)    

        return ret

    # recursively walk up to the root
    def do_walk_to_root(self, node, ret):
        
        parent = node.parent

        if parent:
            ret.append(parent)
            self.do_walk_to_root(parent, ret)
            
    def node_searchfor(self, searchfor, fileids, partial=0):
 
        # if the string doesn't exist this will return null
        if partial:
            # this would a nice join if we had just one database...
            sids   = self.obj.stringtable.search_ids(searchfor)

            if not sids:
                return
           
            if len(sids) > 999:
                raise MsgBoxError("The given search returned over 1000 results. Please narrow your search.")
 
            query = "select nodeid from treenodes where "

            sidstr = "stringid in (" + ",".join(["%d" % sid for sid in sids]) + ")"

            query = query + sidstr

            #print "query is %s" % query
            self.db.cursor.execute(query)

        else:
            sid    = self.stringtable.string_id(searchfor)
        
            if not sid:
                return

            self.db.cursor.execute("select nodeid from treenodes where stringid=?",(sid,))

        nodeids = self.query_results_all()

        for nid in nodeids:
            node = self.idxtonode(nid)

            if self.check_fileids(node, fileids):
                yield node
    
    # searches for searchfor and returns parents of it blah blah
    # returns [] if searchfor is not a key
    #ret = obj.tree.walk_to_root_search('b',[0])    
    #for r in ret:
    #    for node in r:
    #        print "%s" % obj.stringtable.idxtostr(node.sid)
    def walk_to_root_search(self, searchfor, fileids):

        ret    = []

        for node in self.node_searchfor(searchfor, fileids):

            # get path list
            l = self.walk_node_to_root(node)

            # reverse it to be in order
            l.reverse()

            ret.append(l)
                
        return ret


    # walks ALL children (unlimited depth) unless stopnum is used
    def walk_children(self, node, fileids, depth=10000):
       
        ret = {}    
          
        self.do_walk_children(node, fileids, depth, ret)

        return ret

    def do_walk_children(self, node, fileids, depth, ret):
        
        if depth == 0:
            return
        
        depth = depth - 1
    
        # parent node
        nid = node.nodeid

        # will error on keys with no children
        try:
            childids = self.pid_cache[nid]
        except:
            return
          
        for childid in childids:

            child = self.idxtonode(childid)

            if self.check_fileids(child, fileids):

                if not nid in ret:
                    ret[nid] = [child]
                else:
                    ret[nid].append(child)
                
                self.do_walk_children(child, fileids, depth, ret)
        
    # used if the node id is known
    def walk_children_nodeid(self, nodeid, fileid, depth=10000):

        node = self.idxtonode(nodeid)
        
        return self.walk_children(node, fileid, depth)        

    def walk_children_search(self, searchfor, fileids, partial=0):
        
        ret = []

        for node in self.node_searchfor(searchfor, fileids, partial):
            
            ret.append(self.walk_children(node,fileids))

        return ret

    def walk_children_search_partial(self, searchfor, fileids):
        
        return self.walk_children_search(searchfor, fileids, 1)
    
    def walk_children_path(self, path, fileids, depth=10000): 
        ret = []
        # get id for last node in path
        nodes = self.check_path_from_root(path, fileids)

        if nodes: 
            lnode = nodes[-1]
            ret.append(self.walk_children_nodeid(lnode.nodeid, fileids, depth))
        
        return ret

class nodeobj:

    # objects get .nodeid when added to a tree
    # keys (last part of paths) get timestamps
    def __init__(self, fileid, sid):

        self.sid       = sid
        self.parent    = None
        
        # list of fileids this node belongs to
        self.fileids = [fileid]
        
        self.timestamps = {}

class blah:
    pass

def main():

    o = blah()
    o.stringtable = stringtbl("/tmp/abc")
    
    t = ptree(o)

    r = blah()
    r.path = ["a","b","c","d"]

    t.add_path(1, r)

    r.path = ["a","b","c","d"]
    t.add_path(1, r)

    o.stringtable.commit_db()


if __name__ == "__main__":
    main()



