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
from registrydecoder.errorclasses import *
from registrydecoder.regconstants import *

import registry_sig
import acquirefiles.acquire_files as aqfile
import shutil, sys, re, os

import registrydecoder.common as common

from subprocess import call

import pytsk3
import ewf
import traceback
import shutil

class acquire_files:

    def __init__(self):
        self.singlefilecounter = 0
        self.reg_sig = registry_sig.registry_sig()
        self.ac = None

    def add_single_file(self, evidence_file, evidence_type, gui_ref):

        # write the info.txt information
        directory = os.path.join(gui_ref.directory, "registryfiles", "singlefiles")
        try:
            os.makedirs(directory)
        except:
            pass

        filename = os.path.join(directory,"info.txt")
        fd = open(filename,"a",0750)

        mtime = int(os.path.getmtime(filename))
    
        fd.write("%s\t%d\t%d\n" % (evidence_file, mtime, self.singlefilecounter))

        fd.close()

        # copy the evidence file into the case directory
        # copy2 copies mac time as well as the file
        filename = os.path.join(directory,"%d" % self.singlefilecounter)

        shutil.copy2(evidence_file,filename)
        
        self.singlefilecounter = self.singlefilecounter + 1
    
    def is_mbr(self, filepath):
        ret = False

        fd = open(filepath, "rb")
        fd.seek(446, 0)

        status = fd.read(1)
        if len(status) == 1 and ord(status) in [0x00, 0x80]:
            fd.seek(510, 0)
    
            sig = fd.read(2)
            if ord(sig[0]) == 0x55 and ord(sig[1]) == 0xAA:
                ret = True

        return ret
       
    def is_partition_image(self, evidence_file):
        isimage = 1

        try:
            img = pytsk3.Img_Info(evidence_file)
            pytsk3.FS_Info(img)
        except:
            isimage = 0
            #print "Not a disk image: ", sys.exc_info()[:2]

        return isimage

    # checks if given file is a partition image
    def is_disk_image(self, evidence_file):
        return self.is_mbr(evidence_file) or self.is_partition_image(evidence_file)

    def _run_dump_files(self, evidence_file, gui_ref):
        # kick off dumpfiles
        volpath = gui_ref.UI.volatility_path 
       
        (memfile, volprofile) = evidence_file.strip("\n\r").split(",")

        olddir = os.getcwd()
        
        os.chdir(volpath)
        output = open("outputfile", "w")

        try:
            os.mkdir("dumpdir")
        except:
            pass

        call(["python", "vol.py", "-f", memfile, "--profile", volprofile, "dumpfiles", "-D", "dumpdir", "-S", "summaryfile"], stderr = output, stdout = output) 
       
        summary = open("summaryfile", "r").readlines()
        
        print "changing back to %s" % olddir
        os.chdir(olddir)
    
        return summary

    def _parse_summary(self, voldir, summary):
        ret = []

        hives = ["SOFTWARE", "SYSTEM", "SECURITY", "NTUSER.DAT", "SAM", "USRCLASS.DAT"]

        # read in summary files, rename hives based on read-in
        for line in summary:
            try:
                (_addr, _num, mpath, fullpath) = line.strip().split(",")
            except:
                continue

            ents = mpath.split("\\")
            last = ents[-1]

            # if a registry hive
            if last in hives or last.upper() in hives:
                if last.find("NTUSER") != -1:
                    username = ents[-2]
                else:
                    username = ""

                fullpath = os.path.join(voldir, fullpath)

                ret.append((fullpath, username, last))

        return ret

    def _create_memory_schema(self, conn, cursor):
        cursor.execute("select sql from sqlite_master where type='table' and name=?", ["memory_sources"])    
    
        if not cursor.fetchall():
            tables = ["memory_sources (filename text,  id integer primary key asc)",
                      "registry_files (filename text,  username text, realname text, evi_id int, id integer primary key asc)" ]

            for table in tables:
                cursor.execute("create table " + table)
             
            conn.commit()

    def _insert_mem_file(self, cursor, evidence_file):
        cursor.execute("insert into memory_sources (filename) values (?)", [evidence_file])
        return cursor.execute("SELECT last_insert_rowid()").fetchone()[0] 

    def add_memory_file(self, evidence_file, gui_ref):
        summary = self._run_dump_files(evidence_file, gui_ref)

        hives = self._parse_summary(gui_ref.UI.volatility_path, summary)
                         
        (conn, cursor) = common.connect_db(os.path.join(gui_ref.directory, "registryfiles"), "memory_image_files.db")

        self._create_memory_schema(conn, cursor) 

        evi_id = self._insert_mem_file(cursor, evidence_file.split(",")[0])

        for hive in hives:
            query = "insert into registry_files (filename, username, realname, evi_id) values (?,?,?,?)"
            cursor.execute(query, hive + (evi_id,))

        conn.commit()

    # tries to determine the file type of 'evidence_file' based on
    # extension 
    def determine_type_ext(self, evidence_file):

        extension = os.path.splitext(evidence_file)[-1].lower()

        if extension in (".img",".dd",".raw") or re.search('^(.e\d{1,})$', extension):
            etype = [DD]

        elif extension  == ".db":
            etype = [RDB]
        
        elif extension == ".vmem":
            etype = [MEMORY]

        elif self.is_disk_image(evidence_file): 
            etype = [DD]

        else:
            etype = None

        return etype
        
    def determine_type_sig(self, evidence_file):
        # check for a registry file
        ret = self.reg_sig.determine_type(evidence_file)

        if not ret:
            ret = [UNKNOWN]

        return ret                

    def continuebox(self, evidence_file, gui_ref):
        cont = gui_ref.UI.yesNoDialog("Unable to process %s" % evidence_file, "Would you like to skip this file?") 

        if cont:
            return -1
        else:
            gui_ref.UI.msgBox("Unable to process evidence file %s. Exiting." % evidence_file)
            raise RegAcquireError(evidence_file)
    
    # this gathers the evidence from input files for second stange processing
    def acquire_from_file(self, evidence_file, gui_ref):
        if evidence_file.find(".vmem") > 0:
            self.add_memory_file(evidence_file, gui_ref)
            return [MEMORY]

        evidence_type = self.determine_type_ext(evidence_file)
        
        if not evidence_type:
            evidence_type = self.determine_type_sig(evidence_file)

        if evidence_type[0] == UNKNOWN:
            evidence_type = self.continuebox(evidence_file, gui_ref)
  
        elif evidence_type[0] == DD:
            # pytsk3
            self.ac = aqfile.acquire_files(gui_ref.directory, gui_ref)
            
            # command line
            if not hasattr(gui_ref, "UI"):
                acq_current = gui_ref.acquire_current
                acq_backup  = gui_ref.acquire_backups
            else:
                acq_current = gui_ref.UI.acquire_current
                acq_backup  = gui_ref.UI.acquire_backups

            # this hits on a broken filesystem
            try:
                self.ac.acquire_files(evidence_file, acq_current, acq_backup)
            except Exception, e:
                print "BUG! when attempting to acquire files: %s" % str(e)
                traceback.print_exc(file=sys.stdout)
                evidence_type = self.continuebox(evidence_file, gui_ref)                    

        elif evidence_type[0] == SINGLEFILE:
            self.add_single_file(evidence_file, evidence_type[1], gui_ref)            
           
        # keep a list of RDB files added
        elif evidence_type[0] == RDB:
            fd = open(os.path.join(gui_ref.directory, "registryfiles", "rdb-files.txt"), "a+")            
            fd.write(evidence_file + "\n")
            fd.close() 

        return evidence_type





