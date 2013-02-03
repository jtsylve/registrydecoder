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
#!/usr/bin/python

import sys,os,cPickle,time,struct,sqlite3

from registrydecoder.datastructures.valuestable import *
from registrydecoder.datastructures.paralleltree import *
from registrydecoder.datastructures.strings.stringtable import *
from registrydecoder.errorclasses import *
from registrydecoder.regconstants import *

import registrydecoder.common

import acquire_files as acquire_reg_files
import evidence_database

# whether to profile the run through command line
profile = 0

class objclass:
    pass

class case_processing:

    def __init__(self, UI):
        self.UI = UI
        self.acquire_files = acquire_reg_files.acquire_files()
        self.evidence_db   = evidence_database.evidence_database(self.UI)
                        
    def create_tree_databases(self, case_directory):
        
        databases = ["namedata", "treenodes"]
        i = 0

        for database in databases:
            dbname = os.path.join(case_directory, database + ".db")
            conn = sqlite3.connect(dbname)
            cursor = conn.cursor()

            cursor.execute("PRAGMA default_cache_size=20000")
            cursor.execute("PRAGMA synchronous=OFF")
            cursor.execute("PRAGMA count_changes=OFF")
            cursor.execute("PRAGMA journal_mode=MEMORY")
            cursor.execute("PRAGMA temp_store=2")

            if i == 0:
                try:        
                    cursor.execute("create table keyvalues (namesid int, fileid int, rawsid int , asciisid int, regtype text, id integer primary key asc)")
                    cursor.execute("create index keyvalindex on keyvalues (nodeid,fileid)")
                except:
                    pass
            elif i == 1:
                try:
                    cursor.execute("create table treenodes (nodeid int unique, parentid int, stringid int, id integer primary key asc)")
                    cursor.execute("create index treeindex on treenodes (nodeid, parentid, stringid)") 
                except:
                    pass
            i = i + 1

            conn.commit()

    def insert_tree_nodes(self, case_obj):

        pid_cache = {}

        conn = sqlite3.connect(os.path.join(case_obj.case_directory,"treenodes.db"))
        cursor = conn.cursor()

        for key in case_obj.tree.past_queries:
            
            (pid, sid) = [int(x) for x in key.split("|")]
            node   = case_obj.tree.past_queries[key]
            nodeid = node.nodeid   
               
            if not pid in pid_cache:
                pid_cache[pid] = []

            pid_cache[pid].append(nodeid)
 
            try:
                cursor.execute("insert into treenodes (nodeid, parentid, stringid) values(?,?,?)", (nodeid, pid, sid))
            except sqlite3.IntegrityError:
                pass

        conn.commit()

        case_obj.tree.pid_cache = pid_cache

    # refill past_queries from previous values
    def reinit_trees(self, obj):

        conn = sqlite3.connect(os.path.join(obj.case_directory, "treenodes.db"))
        cursor = conn.cursor()

        cursor.execute("select nodeid, parentid, stringid from treenodes")

        for (nid, pid, sid) in cursor.fetchall():

            key = "%d|%d" % (pid, sid)
            obj.tree.past_queries[key] = obj.tree.idxtonode(nid)

    def reinit_vals(self, obj):

        conn   = sqlite3.connect(os.path.join(obj.case_directory, "namedata.db"))
        cursor = conn.cursor()

        cursor.execute("select namesid, rawsid, asciisid, regtype, id from keyvalues") 
        
        for (nid, rid, aid, regtype, vid) in cursor.fetchall():

            key = "%d|%d|%d|%s" % (nid, aid, rid, regtype)
            
            obj.vtable.vals_hash[key] = vid

    def reinit_htables(self, obj):
        self.reinit_trees(obj)
        self.reinit_vals(obj) 

    def create_tree(self, obj, case_directory):
        self.create_tree_databases(case_directory)

        return ptree(obj)

    def setup_case_obj(self, case_directory):
        case_obj = objclass()
        
        case_obj.case_directory = case_directory
    
        case_obj.stringtable = stringtbl(case_directory)
        case_obj.vtable      = valuesholder(case_obj)
        case_obj.tree        = self.create_tree(case_obj, case_directory)
    
        return case_obj
    
    def perform_processing(self, create_case_ref):
        self.evidence_db.UI = create_case_ref.UI
        
        self.evidence_db.update_output("Starting Processing")
    
        if create_case_ref.add_evidence: 
            case_obj = self.createcase.processCaseInfo(create_case_ref.directory, 1)
            self.reinit_htables(case_obj) 
        else:
            case_obj = self.setup_case_obj(create_case_ref.directory)

        ehash = {}

        numfiles = len(self.UI.evidence_list)

        i = 0
        skip_indexes = []
        # grab each peice of evidence given and process it based on type
        for evidence_file in self.UI.evidence_list:        
        
            self.evidence_db.update_output("Processing File %d of %d" % (i+1, numfiles))

            etype = self.acquire_files.acquire_from_file(evidence_file, create_case_ref)

            # user chose to skip the file
            if etype == -1:
                skip_indexes.append(i)

            # user chose not to skip file, need to force re-adding of evidence
            elif etype == -2:
                raise RegBadEvidenceError(evidence_file)

            else:
                etype = etype[0]
                if evidence_file.find(",") != -1:
                    efile = evidence_file.split(",")[0]
                else:
                    efile = evidence_file

                ehash[efile] = etype
    
            i = i + 1

        if self.acquire_files.ac:
            ac = self.acquire_files.ac
            ac.cursor.close()
            ac.cursor = None
            ac.conn   = None

        # remove files that could not be processed
        self.UI.evidence_list = [item for idx,item in enumerate(self.UI.evidence_list) if idx not in skip_indexes]

        # check if any valid files were added
        if len(self.UI.evidence_list) == 0:
            create_case_ref.UI.msgBox("No valid files were added as evidence. Cannot Proceed.")
            raise RegBadEvidenceError("No valid files")

        # write out evidence information to evidence_database.db
        self.evidence_db.write_evidence_database(create_case_ref, ehash, case_obj)
        
        self.evidence_db.update_output("Saving Information")

        self.insert_tree_nodes(case_obj)

        # delete lists and such that aren't needed anymore
        case_obj.tree.before_pickle()
        
        self.evidence_db.update_output("Final Processing")

        pickle_name = os.path.join(case_obj.case_directory,"caseobj.pickle")
        writefd = open(pickle_name,"wb")    
        cPickle.dump(case_obj, writefd, 2)
        writefd.close()

        return True


