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
import sys, os, struct, copy, re

import pytsk3
import common

from errorclasses import *
from image_classes import * 

class acquire_files:

    def __init__(self, case_dir, gui_ref):
        self.regfile_ctr = 0
        self.img_ctr     = 0 

        if hasattr(gui_ref, "gui"):
            self.gui = gui_ref.gui
        else:
            self.gui = None

        self.store_dir = os.path.join(case_dir, "registryfiles")

        # thismakes testing easier to avoid exception        
        try:
            os.mkdir(self.store_dir)
        except:
            pass

        self.db_ops()      

    def db_ops(self):
 
        (self.conn, self.cursor) = common.connect_db(self.store_dir, "acquire_files.db")
        
        self.cursor.execute("select sql from sqlite_master where type='table' and name=?", ["evidence_sources"])
       
        # need to iniitalize the table of files
        # nothing to do if already created
        if not self.cursor.fetchall():
            
            tables = ["evidence_sources (filename text,   id integer primary key asc)",
                      "partitions       (number int, offset int, evidence_file_id int, id integer primary key asc)",
                      "file_groups      (group_name text, partition_id int, id integer primary key asc)",
                      "reg_type         (type_name text, file_group_id int, id integer primary key asc)",
                      "rp_groups        (rpname text, reg_type_id int, id integer primary key asc)",
                      "registry_files   (filename text,  mtime text, reg_type_id int, file_id int, file_type int, id integer primary key asc)",
                     ]
    
            for table in tables:
                self.cursor.execute("create table " + table)
                
            self.conn.commit()

    def new_partition(self, number, offset):

        evi_id = self.evidence_id

        self.cursor.execute("insert into partitions (number, offset, evidence_file_id) values (?, ?, ?)", [number, offset, evi_id])

        return self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]

    def new_group(self, group_name):

        part_id = self.partition_id

        self.cursor.execute("insert into file_groups (group_name, partition_id) values (?,?)", [group_name, part_id])

        return self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]

    def new_rp(self, rpname, rtype_id):

        self.cursor.execute("insert into rp_groups (rpname, reg_type_id) values (?,?)", [rpname, rtype_id])

        return self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]

    # ex: "core", id of "Current"
    def type_id(self, type_name, group_id):

        self.cursor.execute("select id from reg_type where type_name=? and file_group_id=?", [type_name, group_id])

        res = self.cursor.fetchone()
        
        # group doesn't exist for evidence file
        if not res:
            self.cursor.execute("insert into reg_type (type_name, file_group_id) values (?,?)", [type_name, group_id])
            ret_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0]
        
        else:
            ret_id = res[0]

        return ret_id

    # type -- 
    def insert_reg_file(self, type_name, tid, file_name, file_type, mtime):

        # file_type
        # 0 - regular file
        # 1 - restore point file

        file_id = self.regfile_ctr

        self.cursor.execute("insert into registry_files (filename, reg_type_id, file_id, file_type, mtime) values (?,?,?,?,?)", [file_name, tid, file_id, file_type, mtime])

        self.regfile_ctr = self.regfile_ctr + 1

    # based on pytsk3 documentation
    # returns the file as a python string
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
                    print "BUG: could not find a valid name for %s" % fpath
                    #raise RDError("BUG: could not find a valid name for %s" % fpath)
                
                f = None

        return f
     
    def grab_file(self, f, type_name, fname, group_id, is_rp=0, realname=""):

        data = self.read_file(f)
 
        if data == "":
            print "grab_file: unable to acquire file %s from %s" % (fname, type_name)
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
        
        # notes about this
        # is_rp controls whether its a file from a sys RP
        # group_id for non-rp is core/ntuser in the first level
        # group_id is last level for rp files

        # put info into database
        if not is_rp:
            tid = self.type_id(type_name, group_id)
        else:
            tid = group_id

        self.insert_reg_file(type_name, tid, fname, is_rp, mtime)
    
    def acquire_core_files(self, fs, group_id):
       
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

                self.grab_file(f, "CORE", fname, group_id)

                founddir = 1
                
            if founddir:
                return
                 
    def acquire_user_files(self, fs, group_id):
        
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

                        self.grab_file(ff, "NTUSER", "NTUSER.dat", group_id, realname=fname)

    # get the active core & user registry files
    def acquire_active_files(self, fs):

        # make "Current" file_group
        group_id = self.new_group("Current")

        self.refreshgui()
        self.acquire_core_files(fs, group_id)
        self.refreshgui()
        self.acquire_user_files(fs, group_id)
        self.refreshgui()

    # grabs each registry file from an RP###/snapshot directory
    def parse_rp_folder(self, fs, directory, rpname, group_id):

        if directory.info.meta:
            # open file as a directory
            directory = fs.open_dir(inode=directory.info.meta.addr)
        else:
            print "parse_rp_folder: unable to get %s" % rpname
            return 

        # puts the "RP###" folder under the _restore directory
        rp_id = self.type_id(rpname, group_id)

        core_id   = self.new_rp("CORE",   rp_id)
        ntuser_id = self.new_rp("NTUSER", rp_id)

        # walk the snaphsot dir
        for f in directory:
            
            fname = f.info.name.name

            if fname.startswith("_REGISTRY_MACHINE_"):
                fname = fname[len("_REGISTRY_MACHINE_"):]
                self.grab_file(f, rpname, fname, core_id, is_rp=1)
    
            elif fname.startswith("_REGISTRY_USER_"):
                fname = fname[len("_REGISTRY_USER_"):]
                self.grab_file(f, rpname, fname, ntuser_id, is_rp=1)

    # parse RP structure
    def parse_system_restore(self, fs, directory, group_id):

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

                # only process still allocated restore points
                if subdir.info.meta and (int(subdir.info.meta.flags) & 1) == 1: 
                    subdir = fs.open_dir(inode=subdir.info.meta.addr)

                    for f in subdir:

                        name = f.info.name.name

                        if name == "snapshot":
               
                            # grab the registry files
                            self.parse_rp_folder(fs, f, fname, group_id)
                else:
                    if not subdir.info.meta:
                        flags = -42
                    else:
                        flags = subdir.info.meta.flags

                    print "skipping dir %s | %d" % (fname, flags)
            

    def handle_sys_restore(self, fs):


        directory = fs.open_dir("System Volume Information")

        # this will hit restore files for XP
        for f in directory:
            
            fname = f.info.name.name

            if fname.startswith("_restore{"):
                group_id = self.new_group(fname)
                self.parse_system_restore(fs, f, group_id)

    def handle_reg_back(self, fs):

        dirs  = ["Windows", "System32", "config", "RegBack"]
        files = ["DEFAULT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM"]

        group_id = -1

        # Only Vista/7/2k8 will have this
        try:
            directory = fs.open_dir("/".join(dirs))
        except:
            return

        for f in directory:

            # an initial install of windows 7 had 0 sized regback files...
            if f.info.meta.size == 0:
                continue
        
            # if this is the first file we found
            if group_id == -1:
                 group_id = self.new_group("RegBack")

            fname = f.info.name.name

            if fname in files:
                self.grab_file(f, "CORE", fname, group_id)
        
    def acquire_backup_files(self, fs):

        self.refreshgui()
        self.handle_sys_restore(fs)
        self.refreshgui()
        self.handle_reg_back(fs)

    def refreshgui(self):

        if not self.gui:
            return

        self.gui.update()
        self.gui.app.processEvents()
        self.gui.update()
        self.gui.app.processEvents()
        
    def is_e01file(self, filepath):

        base, ext = os.path.splitext(filepath)

        return  re.search('^(.E\d{1,})$', ext)

    def is_splitfile(self, filepath):

        base, ext = os.path.splitext(filepath)
    
        return  re.search('^(.\d{1,})$', ext)


    def get_names(self, filepath, func):

        dirname = os.path.dirname(filepath)

        files = []

        # only find files in the immediate directory
        for root, dirs, filenames in os.walk(dirname):

            for filename in filenames:

                if func(filename):

                    files.append(os.path.join(dirname, filename))

        # so ugly that this is done in-place
        files.sort()
            
        return files

    def get_img_info(self, filepath):

        # encase
        if self.is_e01file(filepath):
           
            # we need to grab all the files of type this
            files = self.get_names(filepath, self.is_e01file)
          
            try: 
                img = EWFImgInfo(*files)

            except Exception, e:
                print "BUG: Couldnt create EWFImgInfo: %s" % str(e)
                

            print "img is %s" % str(img)

        # split
        elif self.is_splitfile(filepath):

            files = self.get_names(filepath, self.is_splitfile)
            
            img = SplitImage(*files)

        # regular dd/raw
        else:
            img = pytsk3.Img_Info(filepath)

        return img

    def get_offsets(self, img):

        offsets = []

        # if its a disk image, this will get the offset of all the partitions
        # if its a partition imge (e.g. /dev/sda1), it will return [0] since it starts at beginning
        try:
            # volume info (partitions) 
            volinfo = pytsk3.Volume_Info(img)
        except Exception, e:
            print "BUG: Couldnt create vol_info: %s" % str(e)
            return [(0, 0)]

        block_size = volinfo.info.block_size

        # this our attempt to keep track of the partition number as would be shown with 'fdisk -l'
        # sleuthkit uses a different schema where 'meta' entries become partitions
        part_num = 0

        for part in volinfo:

            start = part.start * block_size

            if part.flags == 1: # allocated, not meta
                offsets.append((part_num, start))
   
            if part.flags in (1,2): # TSK_VS_PART_FLAG_ALLOC or TSK_VS_PART_FLAG_UNALLOC 
                part_num = part_num + 1
             
        return offsets

    # gather all the files from the system
    # auto detect OS of image
    def acquire_files(self, filepath, current, backup):

        # get the image type (raw, encase, split)
        img = self.get_img_info(filepath)        
      
        offsets = self.get_offsets(img)
 
        # this needs to be expanded if we support dual boot disk images
        # insert the file and the kept the id around
        self.cursor.execute("insert into evidence_sources (filename) values (?)", [filepath])
        self.evidence_id = self.cursor.execute("SELECT last_insert_rowid()").fetchone()[0] 

        for (part_num, offset) in offsets:

            self.partition_id = self.new_partition(part_num, offset)

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

