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
#!/usr/bin/python

import sys,os,cPickle,time,struct,sqlite3

import initial_processing.acquire_files as acquire_reg_files
import initial_processing.evidence_database as evidence_database

from PyQt4.QtCore import *
from PyQt4.QtGui import *

from datastructures.values.valuestable import *
from datastructures.tree.paralleltree import *
from datastructures.strings.stringtable import *
from guicontroller import *
import common

# whether to profile the run through command line
profile = 0

class objclass:
    pass

class case_processing:

    def __init__(self):
        self.acquire_files = acquire_reg_files.acquire_files()
        self.evidence_db   = evidence_database.evidence_database()
                        
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
                cursor.execute("create table keyvalues (nodeid int, namesid int, fileid int, rawsid int , asciisid int, regtype text, id integer primary key asc)")
                cursor.execute("create index keyvalindex on keyvalues (nodeid,fileid)")
            elif i == 1:
                cursor.execute("create table treenodes (nodeid int unique, parentid int, stringid int, id integer primary key asc)")
                cursor.execute("create index treeindex on treenodes (nodeid, parentid, stringid)") 
        
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
 
            cursor.execute("insert into treenodes (nodeid, parentid, stringid) values(?,?,?)", (nodeid, pid, sid))

        conn.commit()

        case_obj.tree.pid_cache = pid_cache

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
    
    def perform_processing(self, gui_ref):

        self.evidence_db.update_label(gui_ref.gui, "Starting Processing")

        case_obj = self.setup_case_obj(gui_ref.directory)

        ehash = {}

        numfiles = len(gui_ref.evidence_list)

        i = 0
        skip_indexes = []
        # grab each peice of evidence given and process it based on type
        for evidence_file in gui_ref.evidence_list:        
        
            self.evidence_db.update_label(gui_ref.gui, "Processing File %d of %d" % (i+1, numfiles))
            
            # grab all the registry files from each file or the registry file itself
            etype = self.acquire_files.acquire_from_file(evidence_file, gui_ref)

            # user chose to skip the file
            if etype == -1:
                skip_indexes.append(i)

            # user chose not to skip file, need to force re-adding of evidence
            elif etype == -2:
                return False                

            else:
                etype = etype[0]
                ehash[evidence_file] = etype
            
            i = i + 1
        
        # remove files that could not be processed
        gui_ref.evidence_list = [item for idx,item in enumerate(gui_ref.evidence_list) if idx not in skip_indexes]

        # check if any valid files were added
        if len(gui_ref.evidence_list) == 0:
            gui_ref.gui.msgBox("No valid files were added as evidence. Cannot Proceed.")
            return False

        # write out evidence information to evidence_database.db
        self.evidence_db.write_evidence_database(gui_ref, ehash, case_obj)
        
        self.evidence_db.update_label(gui_ref.gui, "Saving Information")

        self.insert_tree_nodes(case_obj)

        # delete lists and such that aren't needed anymore
        case_obj.tree.before_pickle()
        
        self.evidence_db.update_label(gui_ref.gui, "Final Processing")

        pickle_name = os.path.join(case_obj.case_directory,"caseobj.pickle")
        writefd = open(pickle_name,"wb")    
        cPickle.dump(case_obj, writefd, 2)
        writefd.close()

        return True

class blah:
    pass

def print_stuff(self, obj):

    #print_vals(obj)

    #draw_graph(obj.ktree,obj)    

    ret  =    obj.ktree.check_path_from_root(["Clients","Contacts","Address Book"],[-1])

def main():

    import templates.util.util as tutilclass

    #image = sys.argv[1]

    g = blah()
    g.acquire_current = 1
    g.acquire_backups = 1
    g.directory       = "/tmp/3/"
    #g.evidence_list   = ["/media/ba42b2b8-ad4d-4ee2-b5de-0c8119467859/win7.dd"]
    g.evidence_list = ["/media/ba42b2b8-ad4d-4ee2-b5de-0c8119467859/XP.dd"]

    case_processing().perform_processing(g)

    '''
    tutil = tutilclass.templateutil(obj)
    
    # tree, path, name, value, [-1]
    
    # this one works
    print tutil.path_key_val_exists(obj.ktree, ["Classes",".323"], "Content Type", "text/h32", [-1])

    # this one should return false
    print tutil.path_key_val_exists(obj.ktree, ["Classes",".323"], "CCCCCCCCCContent Type", "text/h32", [-1])
    '''
    
if __name__ == "__main__":

    if profile:
        import cProfile
        cProfile.run('main()')
    else:
        main()





