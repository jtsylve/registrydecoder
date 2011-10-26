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
import common
import sys, sqlite3, os, types, struct

from datastructures.strings.stringtable import *

class nodevalue:

    def __init__(self, nodeid, namesid, asciisid, rawsid, regtype):

        self.nodeid   = nodeid
        self.namesid  = namesid
        self.asciisid = asciisid
        self.rawsid   = rawsid
        self.regtype  = regtype

class valuesholder:

    def __init__(self, obj):
        self.obj = obj
        self.stringtable = obj.stringtable
        self.db_connect(obj.case_directory)

        self.vid_cache = {}

        self.before_pickle()

    def before_pickle(self):
        self.vals_hash = {}
        
    def db_connect(self, case_dir):

        self.conn   = sqlite3.connect(os.path.join(case_dir, "namedata.db"))
        self.cursor = self.conn.cursor()

        self.cursor.execute("PRAGMA default_cache_size=20000")
        self.cursor.execute("PRAGMA synchronous=OFF")
        self.cursor.execute("PRAGMA count_changes=OFF")
        self.cursor.execute("PRAGMA journal_mode=MEMORY")
        self.cursor.execute("PRAGMA temp_store=2")

    def get_ascii_type(self, asciidata):
        
        if not asciidata:
            return ""
        
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
        
    def record_name_data(self, val):

        if not val.name or val.name == "":
            name = "NONE"
        else:
            if val.name == "ThreadingModel":
                v = 1
            else:
                v = 0

            name = self.get_ascii_type(val.name)
           
        regtype   = val.type_of_data        
        
        asciidata = self.get_ascii_type(val.data)

        if v: 
            print "val.data %s type %s name %s" % (val.data, type(val.data), asciidata)
        
        if val.data and regtype == 3: # REG_BINARY
            rawdata  = "".join(["%.02x" % r for r in val.data])
        else:
            rawdata = asciidata
 
        nid = self.stringtable.getadd_string(name)
        aid = self.stringtable.getadd_string(asciidata)
        rid = self.stringtable.getadd_string(rawdata)

        key = "%d|%d|%d|%s" % (nid, aid, rid, regtype)

        if not key in self.vals_hash:
        
            self.cursor.execute("insert into keyvalues (namesid, rawsid, asciisid, regtype) values (?,?,?,?) ", \
                 (nid, rid, aid, regtype))

            vid = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]
            
            self.vals_hash[key] = vid

        else:
            vid = self.vals_hash[key]

        return vid

    # set the vid for each node
    def create_values(self, node, fileid):

        valuelist  = node.valuelist

        # list of values from reg parser - right pane
        for val in valuelist:
            vid = self.record_name_data(val)
            
            # associate the name/value pair with its node & fileid
            if not vid in node.values:
                node.values[vid] = {}

            if not fileid in node.values[vid]:
                node.values[vid][fileid] = 1

            if not vid in self.vid_cache:
                self.vid_cache[vid] = {}

            if not node in self.vid_cache[vid]:
                self.vid_cache[vid][node] = 1
 
    def or_statement(self, column, int_list):

        fstr = ""

        if int_list:
            fstr = "%s in (" % column
            fstr = fstr + ",".join(["%d" % sid for sid in int_list]) + ") "

        return fstr
       
    def check_fileids(self, node_fileids, good_fileids):

        # not a node for the root
        if good_fileids[0] == -1:
            goodids = None
        else:
            goodids = list(set(good_fileids) & set(node_fileids))

        return goodids

    def values_for_node(self, node, fileids, extra_query=""):

        ret = []
        
        if not node:
            return ret

        for vid in node.values:
    
            cur = []
   
            # get the fileids for this particular value
            node_fileids = node.values[vid].keys()

            if not self.check_fileids(node_fileids, fileids):
                continue
            
            query = "select namesid,asciisid,rawsid,regtype from keyvalues where id=%d " % vid

            query = query + extra_query

            self.cursor.execute(query)

            for v in self.cursor.fetchall():

                cur.append(nodevalue(node.nodeid, v[0], v[1], v[2], v[3]))
        
            ret = ret + cur

        return ret

    def key_name(self, node, name, fileids):

        sid   = self.stringtable.string_id(name)

        if sid:
            ret = self.values_for_node(node, fileids, "and namesid=%d" % sid)
        else:
            ret = None

        return ret

    def key_name_value(self, node, name, value, fileids):

        nid = self.stringtable.string_id(name)
        vid = self.stringtable.string_id(value)

        if vid and nid:
            ret = self.values_for_node(node, fileids, "and namesid=%d and asciisid=%d"  % (nid, vid))
        else:
            ret = None

        return ret

    def nodevals_for_search(self, sidcolumn, searchfor, fileids, partial):

        ret = []
        
        if partial:
            sids = self.stringtable.search_ids(searchfor)
        else:    
            sids = self.stringtable.string_id(searchfor)
            if sids:
                sids = [sids]

        if  sids and sids != -1:
            
            orp = self.or_statement(sidcolumn, sids)

            query = "select id from keyvalues where %s" % orp

            self.cursor.execute(query)

            # the value ids that matched the search
            vids = [x[0] for x in self.cursor.fetchall()]
            
            # remove where the same name/data matched multiple times
            vids = list(set(vids))
            
            # get the value id for all matching nodes
            for vid in vids:
 
                if not vid in self.vid_cache:
                    continue

                nodes = self.vid_cache[vid].keys()

                # get the values for each node
                for node in nodes:

                    ret = ret + self.values_for_node(node, fileids, "and " + orp)

        return ret
            
    def names_for_search_partial(self, searchfor, fileids):
        return self.nodevals_for_search("namesid", searchfor, fileids, 1)

    def names_for_search(self, searchfor, fileids):
        return self.nodevals_for_search("namesid", searchfor, fileids, 0)
    
    def data_for_search_partial(self, searchfor, fileids):
        return self.nodevals_for_search("asciisid", searchfor, fileids, 1)

    def data_for_search(self, searchfor, fileids):
        return self.nodevals_for_search("asciisid", searchfor, fileids, 0)
    
    def rawdata_for_search_partial(self, searchfor, fileids):
        return self.nodevals_for_search("rawsid", searchfor, fileids, 1)
    
    def rawdata_for_search(self, searchfor, fileids):
        return self.nodevals_for_search("rawsid",  searchfor, fileids, 0)
    
    # returns the ascii string
    def get_value_string(self, val):
        return self.stringtable.idxtostr(val.asciisid)
    
    def get_raw_value_string(self, val):
        return self.stringtable.idxtostr(val.rawsid)
    
    def get_name_string(self, val):
        return self.stringtable.idxtostr(val.namesid)
        
    
    
    


    
    

