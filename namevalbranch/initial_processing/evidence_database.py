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
import os,sys,sqlite3,hashlib

from errorclasses import *

from PyQt4.QtCore import *
from PyQt4.QtGui import *

import registry_sig
import tree_handler
import common
import guicontroller

class evidence_database:

    def __init__(self):
        self.reg_sig      = registry_sig.registry_sig()
        self.tree_handler = tree_handler.tree_handling()

    def compute_md5(self, filename):

        oneMB = 1048576
        pos   = 0
        md5   = hashlib.md5()
        size  = os.stat(filename).st_size

        fd = open(filename,"rb")

        while pos < size:

            buf = fd.read(oneMB)

            md5.update(buf)

            pos = pos + oneMB

        return md5.hexdigest()

    def get_file_contents(self, path, filename):

        infofilename = os.path.join(path,filename)

        try:
            os.stat(infofilename)
        except:
            infofilename = None

        if not infofilename:
            ret = None
        else:
            infofile  = open(infofilename,"r")
            ret = infofile.readlines()
    
        return ret    

    def create_evidence_db(self, directory):
        dbname = os.path.join(directory, "evidence_database.db")

        self.conn   = sqlite3.connect(dbname)
        self.cursor = self.conn.cursor()
        
        self.cursor.execute("create table evidence_sources (filename text, file_alias text, evidence_type int, md5sum text, mtime int, id integer primary key asc)")

        # used to group files together from a disk image or db such as 'current' or system restore pointis
        self.cursor.execute("create table file_groups (group_name text, evidence_file_id int, id integer primary key asc)")
        self.cursor.execute("create table registry_files (filename text, registry_type int, md5sum text, mtime text, group_id int, id integer primary key asc)")        
    
        self.conn.commit()
    
    # try to guess the type based on the file - last resort
    def guess_type(self, filepath):
       
        rtypes = guicontroller.registry_types

        for inttype in rtypes:
            name = rtypes[inttype]
        
            if filepath.find(name.lower()) != -1 or filepath.find(name.upper()) != -1:
                return inttype

        return None
      
    # get info for insertion into a database
    def fill_db_info(self, hive_name, fullpath, hashit=1):

        if hashit:
            md5 = self.compute_md5(fullpath)
        else:
            md5 = 0

        mtime         = int(os.path.getmtime(fullpath))
        evidence_type = self.reg_sig.determine_type_file(fullpath)

        # we prefer to have in-file signatures match
        if evidence_type:
            evidence_type = evidence_type[1]
        else:
            evidence_type = self.guess_type(hive_name)

        if not evidence_type and hive_name:
            # TODO ideally we could raise this error, but there are still some files (usrclass, default) that we don't deal with yet
            #raise MsgBoxError("Couldnt find type for %s -> %s" % (hive_name, fullpath))
            print "Couldnt find type for %s -> %s" % (hive_name, fullpath)

        return (md5, mtime, evidence_type)
        
    # insert into the evidence sources table
    def insert_evidence_source(self, filename, hashit=1, ehashfname=""):
       
        # rdb files...
        if ehashfname == "":

            evidence_type = self.ehash[filename]
            md5, mtime, unused = self.fill_db_info("", filename, hashit)
            alias         = self.gui_ref.gui.alias_hash[filename]

        else:
            md5, mtime = (-1, -1)
            alias     = self.gui_ref.gui.alias_hash[ehashfname]
            evidence_type = self.ehash[ehashfname]
            if not alias or alias == "":
                alias = filename    

            filename  = ehashfname


        self.cursor.execute("insert into evidence_sources (filename, file_alias, evidence_type, md5sum, mtime) values (?,?,?,?,?)", \
                    (filename, alias, evidence_type, md5, mtime))

        return self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]

    def insert_file_group(self, group_name, evidence_id):

        self.cursor.execute("insert into file_groups (group_name, evidence_file_id) values (?,?)", (group_name, evidence_id))

        return self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]

    def insert_registry_file(self, filename, mtime, last_id, fullpath):

        md5, unused1, evidence_type = self.fill_db_info(filename, fullpath)
        
        self.cursor.execute("insert into registry_files (filename, registry_type, md5sum, mtime, group_id) values (?,?,?,?,?)", \
                    (filename, evidence_type, md5, mtime, last_id))
        
        file_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]

        return (evidence_type, file_id)
        
    # gets a single registry file and inserts into the database with its group information
    # also handles pickling the file
    def write_single_file(self, case_dir, path, group_id, line):

        (reg_filename, mtime, original_pickle_id) = line.split(",")

        original_pickle_id = original_pickle_id.strip("\r\n")
            
        original_pickle_file = os.path.join(path, original_pickle_id)

        (etype, file_id) = self.insert_registry_file(reg_filename, mtime, group_id, original_pickle_file)

        # not a single file
        if path.find("singlefil") == -1:
            extra = path
        else:
            extra = ""           
 
        self.add_file_to_tree(original_pickle_file, file_id, reg_filename, extra)

    def add_file_to_tree(self, pickle_file, fileid, hivepath, extra):

        first = "File %s" % hivepath
        if extra != "":
            first = first + " from %s" % extra

        self.update_label(self.gui, "Adding " + first)
        ret = self.tree_handler.add_file_to_tree(self.gui, pickle_file, fileid, self.case_obj, first)

        # if the file added correctly then display, if not delete its records from the database
        if ret == True:
            self.update_label(self.gui, "%s Added" % first)
        else:
            self.cursor.execute("delete from registry_files where id=?", (fileid,))                  

    def update_label(self, gui, string):

        if not hasattr(gui,"progressLabel"):
            return
 
        gui.progressLabel.setText(QString(string))

        gui.update()
        gui.app.processEvents()
        gui.update()
        gui.app.processEvents()
        
    # for single files added
    def write_single_to_db(self, case_dir, path):

        lines = self.get_file_contents(path, "info.txt")
        if lines:
            for line in lines:
        
                (filename, a, b) = line.split(",")
                evidence_source_id = self.insert_evidence_source(filename)

                self.update_label(self.gui_ref.gui, "Processing Single File %s" % filename)

                group_name = "SINGLE"
                group_id   = self.insert_file_group(group_name, evidence_source_id)

                self.write_single_file(case_dir, path, group_id, line)

    # this takes info from an acquire_files database and inserts them into a case tree/processing queue
    def handle_image_files(self, casedir, basedir, dbname="acquire_files.db", ehashfname=""):

        # see if any images were added to the evidence list
        try:
            fd = open(os.path.join(basedir, dbname))
        except:
            return

        (conn, cursor) = common.connect_db(basedir, dbname)
        cursor.execute("select filename, id from evidence_sources")
        imgs = cursor.fetchall()
        
        # image files
        for (img_filename, orig_id) in imgs:

            evi_id = self.insert_evidence_source(img_filename, 0, ehashfname)
        
            cursor.execute("select group_name,id from file_groups where evidence_file_id=?", [orig_id])
            groups = cursor.fetchall()

            # each group / evidence id pair
            for (group_name, orig_gid) in groups:

                gid = self.insert_file_group(group_name, evi_id)
        
                cursor.execute("select filename, mtime, file_id from registry_files where group_id=?", [orig_gid])
                file_info = cursor.fetchall()
        
                for (filename, mtime, file_id) in file_info:
                
                    pickle_file = os.path.join(basedir, "%d" % file_id)
                    (etype, file_id) = self.insert_registry_file(filename, mtime, gid, pickle_file)

                    self.add_file_to_tree(pickle_file, file_id, filename, img_filename)

                    conn.commit()

    def handle_rdb_files(self, case_dir):

        # test if any rdb files were added    
        try:
            fd = open(os.path.join(case_dir, "rdb-files.txt"), "r")
        except:
            return

        for dbpath in fd.readlines():

            if dbpath[-1] == '\n':
                dbpath = dbpath[:-1]

            (dirname, fname) = os.path.split(dbpath)

            self.handle_image_files(case_dir, dirname, fname, dbpath)

        fd.close()

    def write_evidence_database(self, gui_ref, ehash, case_obj):

        # this can probably be cleaned up but meh..
        self.case_obj = case_obj
        self.ehash    = ehash
        self.gui_ref  = gui_ref
        self.gui      = gui_ref.gui

        case_dir = gui_ref.directory

        self.create_evidence_db(case_dir)

        basedir = os.path.join(case_dir, "registryfiles")

        path = os.path.join(basedir, "singlefiles")

        # if there were single files added
        if os.path.exists(path):
            self.write_single_to_db(case_dir, path)        
            self.conn.commit()
                    
        self.handle_image_files(case_dir, basedir)
        self.conn.commit()

        self.handle_rdb_files(case_dir)
        self.conn.commit()


