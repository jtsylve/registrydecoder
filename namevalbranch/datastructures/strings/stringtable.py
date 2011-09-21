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
import datastructures.strings.stringdatabase.dbhandler as sdbm

class stringtbl:
    
    def __init__(self, case_dir):
        self.idxlookup = {}
        self.strlookup = {}
        self.sdb = sdbm.dbhandler("sqlite3",case_dir).get_dbhandle()
        self.db_connect(case_dir)
        
        self.hits = 0
        self.misses = 0
        
    def db_connect(self, cd):
        self.sdb.connect_db(cd)

    # sqlite has to commit to the disk explicility
    # but it kills performance to do it after every insert
    def commit_db(self):
        self.sdb.commit_db()

    def add_string(self, instr):

        # inserts into database (if not already there) and returns string id
        sid = self.sdb.insert_string(instr)
        return sid
   
    def precache_values(self):
    
        self.sdb.cursor.execute("select string,id from stringtable order by id limit 128000")
        strings = self.sdb.cursor.fetchall()

        for (searchstr, sid) in strings:
        
            self.idxlookup[sid]       = searchstr
            self.strlookup[searchstr] = sid

    # returns id for string, if it doesn't exist, returns -1
    def string_id(self, searchstr):

        if searchstr in self.strlookup:
            sid = self.strlookup[searchstr]
        else:
            sid = self.sdb.string_id(searchstr)

        #if searchstr in ("services", "Services"):
        #    print "sid %d for %s" % (sid, searchstr)

        # cache value
        if sid != -1:
            self.idxlookup[sid]       = searchstr
            self.strlookup[searchstr] = sid

        return sid
    

    # returns the correspodning string or None
    def idxtostr(self, sid):
        # we do *not* cache from add_string
        # so this only finds searched for strings
        if sid in self.idxlookup:
            ret = self.idxlookup[sid]
        else:
            ret = self.sdb.idxtostr(sid)

        return ret
    
    #
    def nodetostr(self, node):
        return self.idxtostr(node.sid)


    # if searchstr doesn't exists it adds it and returns id of searchstr
    def getadd_string(self, searchstr):

        sid = self.string_id(searchstr)

        if sid == -1:
            sid = self.add_string(searchstr)

        return sid

    def search_ids(self, searchstr):
        
        return self.sdb.search_ids(searchstr)


