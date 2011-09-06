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

profile = 1

class objclass:
    pass

class fileinfo:

    def __init__(self, evi_file, file_alias, group_name, registry_file):

        self.evidence_file = evi_file
        self.file_alias    = file_alias
        self.group_name    = group_name
        self.registry_file = registry_file

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

        self.evidencedb.cursor.execute("select a.filename, a.file_alias, b.group_name, c.filename,c.id from evidence_sources as a, file_groups as b, registry_files as c where c.group_id=b.id and b.evidence_file_id=a.id")

        for (evidence_file, file_alias, group_name, registry_file, fileid) in self.evidencedb.cursor.fetchall():
        
            self.fileid_hash[fileid] = fileinfo(evidence_file, file_alias, group_name, registry_file) 

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

fid = [2]

def print_children(o, node):

    children = o.tree.walk_children(node, fid, 1)

    nname = o.case_obj.stringtable.idxtostr(node.sid)

    print "nodes for %s" % nname

    for c in children:
        for child in children[c]:
            name = o.case_obj.stringtable.idxtostr(child.sid)
            print "\t%s" % name
    

def main():

    case_dir = sys.argv[1]

    o = opencase(case_dir)
    
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



