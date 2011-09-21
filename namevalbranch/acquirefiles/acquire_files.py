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
import sys, os, struct, copy

import pytsk3
import common

from errorclasses import *

class acquire_files:

    def __init__(self, case_dir, gui):
        self.regfile_ctr = 0
        self.img_ctr     = 0 

        self.gui = gui

        self.store_dir = os.path.join(case_dir, "registryfiles")

        # thismakes testing easier to avoid exception        
        try:
            os.mkdir(self.store_dir)
        except:
            pass

        self.db_ops(case_dir)      

    def db_ops(self, case_dir):
 
        (self.conn, self.cursor) = common.connect_db(self.store_dir, "acquire_files.db")
        
        self.cursor.execute("select sql from sqlite_master where type='table' and name=?", ["evidence_sources"])
       
        # need to iniitalize the table of files
        # nothing to do if already created
        if not self.cursor.fetchall():
            
            tables = ["evidence_sources (filename text,   id integer primary key asc)",
                      "file_groups      (group_name text, evidence_file_id int, id integer primary key asc)",
                      "registry_files   (filename text,  mtime text, group_id int, file_id int, id integer primary key asc)",
                     ]
    
            for table in tables:
                self.cursor.execute("create table " + table)
                
            self.conn.commit()

    # enforces unique group_name and evidence_id pairs
    def group_id(self, group_name):

        ''' 
        there has to be a better way to do this
        but "insert or replace" changes the auto increment id
        '''

        evi_id = self.evidence_id

        self.cursor.execute("select id from file_groups where group_name=? and evidence_file_id=?", [group_name, evi_id])

        res = self.cursor.fetchone()
        
        # group doesn't exist for evidence file
        if not res:
            self.cursor.execute("insert into file_groups (group_name, evidence_file_id) values (?,?)", [group_name, evi_id])
            ret_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]
        
        else:
            ret_id = res[0]

        return ret_id

    def insert_reg_file(self, group_name, file_name, mtime):

        gid = self.group_id(group_name)
        file_id = self.regfile_ctr

        self.cursor.execute("insert into registry_files (filename, group_id, file_id, mtime) values (?,?,?,?)", [file_name, gid, file_id, mtime])

        self.regfile_ctr = self.regfile_ctr + 1

    # based on pytsk3 documentation
    # returns the file as a python strings
    def read_file(self, fd):

        data = ""
        offset = 0
        BUFF_SIZE = 1024 * 1024

        if fd.info.meta:
            size = fd.info.meta.size
        else:
            return ""            

        while offset < size:
            available_to_read = min(BUFF_SIZE, size - offset)
            cur = fd.read_random(offset, available_to_read)
    
            if not cur:
                break

            data = data + cur
            offset += len(cur)

        return data

    '''
    this ugly function is b/c windows has a case-insentive FS,
    tsk doesn't so we have to try to read the file as both lower and upper case
    if neither of those appear then we have to bail
    '''

    def open_hive(self, fs, directory, fname, raiseex=1):
            
        fpath = directory + "/" + fname.lower()
        
        try:
            f = fs.open(path=fpath)
        except:

            try:
                fpath = directory + "/" + fname.upper()
                f = fs.open(path=fpath)
            except:
                if raiseex:
                    raise RDError("BUG: could not find a valid name for %s" % fpath)
                
                f = None

        return f
     
    def grab_file(self, f, group_name, fname, realname=""):

        data = self.read_file(f)
 
        if data == "":
            print "grab_file: unable to acquire file %s from %s" % (fname, group_name)
            return

        # copy file to acquire_store
        fd = open(os.path.join(self.store_dir, "%d" % self.regfile_ctr), "wb")
        fd.write(data)
        fd.close()

        if f.info.meta:
            mtime = f.info.meta.mtime
        else:
            mtime = 0

        if realname:
            fname = realname

        # put info into database
        self.insert_reg_file(group_name, fname, mtime) 
    
    def acquire_core_files(self, fs):
       
        # files to get from core dir
        files = copy.deepcopy(common.hive_types)
        files.remove("NTUSER")
        files.remove("USRCLASS")
        files.append("DEFAULT")

        v7dirs = ["Windows", "System32", "config"]
        xpdirs = ["WINDOWS", "System32", "config"] 

        founddir = 0

        for dirs in [v7dirs, xpdirs]: 
            dpath = "/".join(dirs)

            try:
                core_dir = fs.open_dir(path=dpath)
            except:
                continue
                
            for fname in files:
        
                f = self.open_hive(fs, dpath, fname)   
                
                # xp desont have default
                if not f and fname == "DEFAULT":
                    continue

                self.grab_file(f, "CORE", fname)

                founddir = 1
                
            if founddir:
                return
                 
    def acquire_user_files(self, fs):
        
        user_dirs = ["Documents and Settings", "Users"]       

        for d in user_dirs:

            try:
                fd = fs.open_dir(path=d)
            except:
                continue

            if hasattr(fd, "info"):
                dname = fd.info.fs_file.name.name
            elif hasattr(fd, "fs_file"):
                dname = fd.fs_file.info.name.name
            else:
                raise RDError("Unable to get dname")

            # each user directory
            for f in fd:
            
                fname = f.info.name.name

                if fname not in [".", ".."]:

                    flist = [dname, fname]
                    
                    ff = self.open_hive(fs, "/".join(flist), "NTUSER.dat", 0)
   
                    if ff: 
                        # open the user's directory
                        rname = ff.info.name.name

                        self.grab_file(ff, "NTUSER", "NTUSER.dat", fname)

    # get the active core & user registry files
    def acquire_active_files(self, fs):

        self.refreshgui()
        self.acquire_core_files(fs)
        self.refreshgui()
        self.acquire_user_files(fs)
        self.refreshgui()

    # grabs each registry file from an RP###/snapshot directory
    def parse_rp_folder(self, fs, directory, group_name):

        if directory.info.meta:
            # open file as a directory
            directory = fs.open_dir(inode=directory.info.meta.addr)
        else:
            print "parse_rp_folder: unable to get %s" % group_name
            return 

        # walk the snaphsot dir
        for f in directory:
            
            fname = f.info.name.name

            if fname.startswith("_REGISTRY_"):
                self.grab_file(f, group_name, fname)

    # parse RP structure
    def parse_system_restore(self, fs, directory):

        if directory.info.meta:
            # directory is sent in as a pytsk3.File
            directory = fs.open_dir(inode=directory.info.meta.addr)
        else:
            print "parse_system_restore: unable to do anything"
            return

        # this uglyness walks each RP###/snapshot dir and sends to the file grab function
        for subdir in directory:
        
            fname = subdir.info.name.name

            if fname.startswith("RP"):

                if subdir.info.meta: 
                    subdir = fs.open_dir(inode=subdir.info.meta.addr)
                else:
                    print "parse_system_restore: Unable to get addr for %s" % fname
                    return                    

                for f in subdir:

                    name = f.info.name.name

                    if name == "snapshot":
           
                        # grab the registry files
                        self.parse_rp_folder(fs, f, fname)


    def handle_sys_restore(self, fs):

        directory = fs.open_dir("System Volume Information")

        # this will hit restore files for XP
        for f in directory:
            
            fname = f.info.name.name

            if fname.startswith("_restore{"):
                self.parse_system_restore(fs, f)

    def handle_reg_back(self, fs):

        dirs  = ["Windows", "System32", "config", "RegBack"]
        files = ["DEFAULT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM"]

        # Only Vista/7/2k8 will have this
        try:
            directory = fs.open_dir("/".join(dirs))
        except:
            return

        for f in directory:

            # an initial install of windows 7 had 0 sized regback files...
            if f.info.meta.size == 0:
                continue
        
            fname = f.info.name.name

            if fname in files:
                self.grab_file(f, "RegBack", fname)
        
    def acquire_backup_files(self, fs):

        self.refreshgui()
        self.handle_sys_restore(fs)
        self.refreshgui()
        self.handle_reg_back(fs)

    # returns a list offsets for every parittion on the image
    def parse_mbr(self, filepath):

        parts = []

        fd = open(filepath, "rb")

        # seek to beginning of partition table
        fd.seek(446, 0)

        # read in table
        table = fd.read(64)
        
        psize = 16

        for offset in xrange(0, 64, psize):

            part   = table[offset : offset+psize]
            
            lba = struct.unpack("<I", part[8:12])[0] & 0xffffffff

            offset = lba * 512
        
            if offset:
                parts.append(offset)

        return parts

    def is_mbr(self, filepath):

        ret = False

        fd = open(filepath, "rb")

        fd.seek(446, 0)

        status = fd.read(1)

        if ord(status) in [0x00, 0x80]:
           
            fd.seek(510, 0)
    
            sig = fd.read(2)

            if ord(sig[0]) == 0x55 and ord(sig[1]) == 0xAA:
                ret = True

        return ret

    def refreshgui(self):

        self.gui.update()
        self.gui.app.processEvents()
        self.gui.update()
        self.gui.app.processEvents()
        
    # gather all the files from the system
    # auto detect OS of image
    def acquire_files(self, filepath, current, backup):

        # IMG_INFO
        try:
            img = pytsk3.Img_Info(filepath)
        except Exception, e:
            print "IMG_Info: unable to open image %s error %s" % (filepath, str(e))
            return

        if self.is_mbr(filepath):
            offsets = self.parse_mbr(filepath)

        else: # partition image
            offsets = [0]

        # this needs to be expanded if we support dual boot disk images
        # insert the file and the kept the id around
        self.cursor.execute("insert into evidence_sources (filename) values (?)", [filepath])
        self.evidence_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0] 

        for offset in offsets:

            # FS_INFO
            try:
                fs = pytsk3.FS_Info(img, offset)
            except Exception, e:
                print "FS_Info: unable to get offset %d from filepath %s error: %s" % (offset, filepath, str(e))
                continue

            self.refreshgui()        
                                      
            if current:
                self.acquire_active_files(fs)

            if backup:
                self.acquire_backup_files(fs)

            self.conn.commit()    


def main():

    current = 1
    backup  = 1

    acquire_files(sys.argv[2]).acquire_files(sys.argv[1], current, backup)


if __name__ == "__main__":
    main()

