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
import sqlite3, os

class sqlite3class:

    def __init__(self, case_dir):

        self.connect_db(case_dir)
        self.create_database()
        
    def commit_db(self):
        self.conn.commit()

    def apply_pragmas(self):
 
        self.cursor.execute("PRAGMA default_cache_size=50000")
        self.cursor.execute("PRAGMA synchronous=OFF")
        self.cursor.execute("PRAGMA count_changes=OFF")
        self.cursor.execute("PRAGMA journal_mode=MEMORY")
        self.cursor.execute("PRAGMA temp_store=2")

    def connect_db(self, case_dir):
        
        self.filename = os.path.join(case_dir,"stringtable.db")
        self.conn   = sqlite3.connect(self.filename)
        self.cursor = self.conn.cursor()

        self.apply_pragmas()

    # creates the database and writes it to disk
    def create_database(self):

        self.apply_pragmas()

        self.cursor.execute("create table stringtable (string text unique collate nocase, id integer primary key asc)")
        self.cursor.execute("create index searchindex on stringtable (string collate nocase)")

        self.conn.commit()

    def insert_string(self, instr):

        self.cursor.execute("insert or replace into stringtable (string) values (?)",[instr])

        sid = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]
        
        return sid    

    def fetch_one(self):

        ret = self.cursor.fetchone()

        if ret:
            ret = ret[0]
        else:
            ret = -1

        return ret

    def string_id(self, searchstr):
    
        self.cursor.execute("select id from stringtable where string=?",[searchstr])

        res = self.cursor.fetchall()

        #if len(res) != 1:
            #print "got %d hits for %s" % (len(res), searchstr)

        if res and res[0]:
            ret = res[0][0]
        else:
            ret = -1

        return ret
        #return self.fetch_one()

    def search_ids(self, searchstr):

        # allow users to search with wildcards
        searchstr = searchstr.replace("*", "%")

        self.cursor.execute("select id from stringtable where string like ?",["%" + searchstr + "%"])

        res = self.cursor.fetchall()

        # make a list of the actual strings
        if res:
            ret = [x[0] for x in res]
        else:
            ret = None
        
        #print "found %d strings that match %s" % (len(ret), searchstr)

        return ret

    def idxtostr(self, sid):
        
        self.cursor.execute("select string from stringtable where id=?",[sid])
                
        ret = self.fetch_one()

        if ret == -1:
            ret = None

        return ret


        




