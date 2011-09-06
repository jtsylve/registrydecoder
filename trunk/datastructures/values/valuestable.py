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
import sys, sqlite3, os, types, struct, binascii

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
        
    def db_connect(self, case_dir):

        self.conn   = sqlite3.connect(os.path.join(case_dir, "namedata.db"))
        self.cursor = self.conn.cursor()

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
            
        #print " | after | %s | %s" % (type(asciidata), asciidata)
        
        return asciidata
        
    def record_name_data(self, val, node, fileid):

        if not val.name or val.name == "":
            name = "NONE"
        else:
            name = self.get_ascii_type(val.name)
            
        regtype   = val.type_of_data        
        
        asciidata = self.get_ascii_type(val.data)
        
        if val.data and regtype == 3:
            rawdata = binascii.hexlify(val.data)
        else:
            rawdata = asciidata
        
        nid = self.stringtable.getadd_string(name)
        aid = self.stringtable.getadd_string(asciidata)
        rid = self.stringtable.getadd_string(rawdata)

        self.cursor.execute("insert into keyvalues (nodeid, namesid, fileid, rawsid, asciisid, regtype) values (?,?,?,?,?,?) ", \
             (node.nodeid, nid, fileid, rid, aid, regtype))

    # set the vid for each node
    def create_values(self, node, fileid):

        valuelist  = node.value

        # list of values from reg parser - right pane
        for val in valuelist:
            self.record_name_data(val, node, fileid)
        
    def or_statement(self, column, int_list):

        fstr = ""

        if int_list:
            fstr = "( " + ''.join(["%s=%d or " % (column,f) for f in int_list])
            fstr = fstr[:-3]
            fstr = fstr + ")"

        return fstr
       
    # ignore this uglyness....
    def query_fileids(self, query, fileids, sidcolumn="", stringids=[]):
    
        ret = []
        dosids = 0

        fstr = query
        
        if fileids[0] != -1:
            if query:
                fstr = fstr + " and "

            fstr = fstr + self.or_statement("fileid", fileids)
            dosids = 1

        if sidcolumn:
            if dosids:            
                fstr = fstr + " and "

            fstr = fstr + self.or_statement(sidcolumn, stringids)

        #print "select nodeid,namesid,asciisid,rawsid,regtype from keyvalues where %s" % fstr
        self.cursor.execute("select nodeid,namesid,asciisid,rawsid,regtype from keyvalues where %s" % fstr)
      
        for v in self.cursor.fetchall():
            ret.append(nodevalue(v[0], v[1], v[2], v[3], v[4]))
                        
        return ret    

    def values_for_node(self, node, fileids):

        return self.query_fileids("nodeid=%d " % node.nodeid, fileids)

    def key_name(self, node, name, fileids):

        sid = self.stringtable.string_id(name)
        nname = self.stringtable.idxtostr(node.sid)

        if sid:
            ret = self.query_fileids("nodeid=%d and namesid=%d "  % (node.nodeid, sid), fileids)
        else:
            ret = None

        return ret

    def key_name_value(self, node, name, value, fileids):

        nid = self.stringtable.string_id(name)
        vid = self.stringtable.string_id(value)

        if vid and nid:
            ret = self.query_fileids("nodeid=%d and namesid=%d and asciisid=%d "  % (node.nodeid, nid, vid), fileids)
        else:
            ret = None

        return ret

    def nodevals_for_search(self, column, searchfor, fileids, partial):
        
        if partial:
            sids = self.stringtable.search_ids(searchfor)
        else:    
            sids = self.stringtable.string_id(searchfor)
            if sids:
                sids = [sids]

        if sids and sids != -1:
            ret = self.query_fileids("", fileids, column, sids)
        else:
            ret = []

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
        
    
    
    


    
    

