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
import sys, os, struct, cPickle, sqlite3

from datastructures.tree.paralleltree import *

import template_manager as tmmod

profile = 0

class objclass:
    pass

class fileinfo:

    def __init__(self, evidence_file, file_alias, part_num, group_name, type_name, registry_file, rpname=""):

        self.evidence_file = evidence_file
        self.file_alias    = file_alias
        self.part_num      = part_num
        self.group_name    = group_name
        self.type_name     = type_name
        self.registry_file = registry_file
        self.rpname        = rpname

class opencase:

    def __init__(self, case_dir):
        self.directory = case_dir
        self.opencaseobj()

    def open_db(self, database):

        ret = objclass()

        dbname = os.path.join(self.directory, database)

        ret.conn   = sqlite3.connect(dbname)
        ret.cursor = ret.conn.cursor()

        return ret

    def fill_fileid_hash(self):

        self.fileid_hash = {}

        self.evidencedb.cursor.execute(
        "select a.filename, a.file_alias, b.number, c.group_name, d.type_name, d.id from " +
        "evidence_sources as a, partitions as b, file_groups as c, reg_type as d " +
        "where a.id=b.evidence_file_id and b.id=c.partition_id and c.id=d.file_group_id" )

        results = self.evidencedb.cursor.fetchall()

        # all the data before dealing with RPs
        for (evidence_file, file_alias, part_num, group_name, type_name, type_id) in results:
        
            # non-rp image files
            self.evidencedb.cursor.execute("select filename,id from registry_files where reg_type_id=? and hive_type=0", [type_id])
            files = self.evidencedb.cursor.fetchall() 

            for (registry_file,fileid) in files:

                self.fileid_hash[fileid] = fileinfo(evidence_file, file_alias, part_num, group_name, type_name, registry_file) 

            # rp image files 
            self.evidencedb.cursor.execute("select rpname, id from rp_groups")
            rps = self.evidencedb.cursor.fetchall()

            for (rpname, rid) in rps: 
                
                self.evidencedb.cursor.execute("select filename,id from registry_files where reg_type_id=? and hive_type=1", [rid]) 
           
                files = self.evidencedb.cursor.fetchall()

                for (registry_file,fileid) in files:

                    self.fileid_hash[fileid] = fileinfo(evidence_file, file_alias, part_num, group_name, type_name, registry_file, rpname)

        # indivinial files
        cursor = self.evidencedb.cursor

        cursor.execute("select g.id, e.filename, e.file_alias from file_groups as g, evidence_sources as e where g.group_name='SINGLE' and e.id=g.partition_id")

        for (gid, evidence_file, alias) in cursor.fetchall():

            cursor.execute("select id, registry_type, md5sum, mtime from registry_files where hive_type=-1 and reg_type_id=?", [gid])

            for (efileid, rtype, md5sum, mtime) in cursor.fetchall():

                self.fileid_hash[efileid] = fileinfo(evidence_file, alias, -1, "SINGLE", "SINGLE_TYPE", evidence_file)

    def opencaseobj(self):
        filename = os.path.join(self.directory,"caseobj.pickle")
        fd = open(filename,"rb")
        obj = cPickle.load(fd)

        obj.stringtable.db_connect(self.directory)
        obj.vtable.db_connect(self.directory)

        self.evidencedb  = self.open_db("evidence_database.db")
        self.nddb        = self.open_db("namedata.db")
        self.stringdb    = self.open_db("stringtable.db")
        self.treenodedb  = self.open_db("treenodes.db")
        self.caseinfodb  = self.open_db("caseinfo.db")

        self.case_obj    = obj
        
        self.vtable  = obj.vtable
        self.tree    = obj.tree
        self.tree.db = self.treenodedb 

        self.fill_fileid_hash()
        obj.stringtable.precache_values()
        
        self.stringtable    = obj.stringtable
        self.vtable         = obj.vtable
        self.case_directory = self.directory
        

def main():

    case_dir = sys.argv[1]

    o = opencase(case_dir)
   
    print "len: %d" % len(o.tree.nodehash)

    ###
    return

    o.current_fileid = int(sys.argv[3])

    root = o.tree.rootnode(o.current_fileid)

    tm = tmmod.TemplateManager()
    tm.load_templates(o)
    
    templates = tm.get_loaded_templates()
    
    plugin_name = sys.argv[2]
    
    ran = 0
    
    for t in templates:
        #print t.name
        if t.pluginname == plugin_name:
            t.run_me()
            ran = 1
            break

    if ran:
        print "------output for %s------" % plugin_name
        
        for val_list in tm.report_data:
            for val in val_list:
                print val,
            print ""

    else:
        print "invalid plugin given" 


if __name__ == "__main__":

    if profile:
        import cProfile
        cProfile.run('main()')
    else:
        main()



