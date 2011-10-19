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
import sys, os, struct, cPickle, sqlite3, getopt

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

        obj.stringtable.precache_values()
        
        self.stringtable    = obj.stringtable
        self.vtable         = obj.vtable
        self.case_directory = self.directory
        


def usage():

    print "python openmain.py <case directory> <plugin name> <file id> <extra plugin directory (optional)>"
    print "See the instructions file for complete description"
    sys.exit(1)

def main():


    try:
        case_dir    = sys.argv[1]
        plugin_name = sys.argv[2]
        fileid      = int(sys.argv[3])
    except:
        usage()

    try:
        extra = sys.argv[4]
        extra = extra.split(";") 
    except:
        extra = []

    # open the case and get the tree
    o = opencase(case_dir)
    o.current_fileid = fileid

    tm = tmmod.TemplateManager()
    tm.load_templates(o, extra)
    
    templates = tm.get_loaded_templates()
    
    ran = 0
    
    for t in templates:
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



