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
#

import os,sys,stat,time,shutil,traceback
import sqlite3

from registrydecoder.errorclasses import *
import start_processing

class cassInfoHolder:

     def __init__(self, cname, cnum, cinvest, ccomments, cdirectory):
        self.case_name         = cname
        self.case_number       = cnum
        self.case_investigator = cinvest
        self.case_comments     = ccomments
        self.case_directory    = cdirectory

# records general info about a case (number, investigator, comments, etc)
class create_case:

    def __init__(self, UI):
        self.UI = UI

        self.add_evidence = 0
        self.made_db      = 0

    # returns:
    # 0 == bad
    # 1 == normal creating a case
    # 2 == adding evidence to an existing case
    def _check_directory(self, caseinfo, pass_check):
        ret  = 0
        good = 0

        self.directory = caseinfo.case_directory

        try:
            mode = os.stat(self.directory)[stat.ST_MODE]
            good = 1
        except:
            self.UI.msgBox("Specified Directory Does not Exist")

        if good:
            if not mode & stat.S_IWUSR:
                self.UI.msgBox("Unable to write to specified directory")
            
            elif os.listdir(self.directory) and not pass_check:
                # ask the user if they are adding evidence to a new case
                # if not, error out
                # if, return 2
                ok = self.UI.yesNoDialog("Chosen directory already contains files.", "Are you adding files to an existing case? ")
                if ok:
                    self.add_evidence = 1
                    ret = 2
                else:
                    self.UI.msgBox("Non-empty directory specificied. Pleaes choose another.")
            else:
                ret = 1
            
        return ret

    def _create_casedb(self):    
        dbname = "caseinfo.db"
        fulldb = os.path.join(self.directory, dbname)

        if self.made_db:
            # resetting the database with new values
            self.conn   = None
            self.cursor = None
            os.unlink(fulldb)

        self.conn   = sqlite3.connect(fulldb)
        self.cursor = self.conn.cursor()

        self.columns  = ["casename", "casenumber", "investigatorname", "comments", "casedirectory"]

        # build string to create table
        colstring = ''.join([x + " text," for x in self.columns])[:-1]

        self.cursor.execute("create table caseinformation (" + colstring +  ", id integer primary key asc)")            

        self.conn.commit()
        
        self.made_db = 1

    def set_case_info(self, cname, cnum, cinvest, ccoments, cdirectory):
        return cassInfoHolder(cname, cnum, cinvest, ccoments, cdirectory) 

    def _insert_case_info(self, passed, pass_check, caseinfo):

        # keep old investigator info is just adding evidence
        if pass_check or passed == 1:
    
            self._create_casedb()
        
            colstring = ''.join([x + "," for x in self.columns])[:-1]
        
            self.cursor.execute("insert into caseinformation (%s) values (?,?,?,?,?)"\
                 % colstring, (\
                caseinfo.case_name, \
                caseinfo.case_number,\
                caseinfo.case_investigator,\
                caseinfo.case_comments,\
                caseinfo.case_directory,
                ))

            self.conn.commit()
 
    # handles inserting information about the general case info
    # caseinfo is of type cassInfoHolder and is obtained through a set_case_info call
    # pass_check is set when re-adding evidence to a case
    def processCaseInfo(self, caseinfo, pass_check = 0):
        passed = self._check_directory(caseinfo, pass_check)
   
        if passed == 1 or pass_check:
            self._insert_case_info(passed, pass_check, caseinfo)

        return passed

    ### class caseSummary from original GUI ###
    
    # http://code.activestate.com/recipes/193736-clean-up-a-directory-tree/
    def _rmgeneric(self, path, __func__):
        __func__(path)
                
    def _removeall(self, path):
        if not os.path.isdir(path):
            return
        
        files = os.listdir(path)

        for x in files:

            if x == "caseinfo.db":
                continue

            fullpath=os.path.join(path, x)
            if os.path.isfile(fullpath):
                f=os.remove
                self._rmgeneric(fullpath, f)
            elif os.path.isdir(fullpath):
                self._removeall(fullpath)
                f=os.rmdir
                self._rmgeneric(fullpath, f)

    def setupCaseDir(self):
        ret = 0

        regdir = os.path.join(self.directory, "registryfiles")

        # this errors if the user added bad evidence and then redoes processing
        try:
            os.mkdir(regdir)
        except:
            # the case_obj stuff gets reinitialized after button is pressed
            if self.add_evidence == 0:
                try:
                    #self.removeall(self.directory)
                    os.mkdir(regdir)
                except:
                    self.UI.msgBox("WARNING: Registry Decoder was unable to remove the scratch directory. New evidence cannot be added to this case unless you manually remove the 'registryfiles' directory in your case folder.")     
                    return ret
        try:
            os.mkdir(os.path.join(regdir,"singlefiles"))
        except:
            self.UI.msgBox("WARNING: Registry Decoder was unable to create the singlefiles directory. Please check that you have write permission to the case folder.")

        return 1    

    ### class create_case from original GUI ###
    def process_case_files(self):
        # try to add the given evidence
        try:
            start_processing.case_processing(self.UI).perform_processing(self)  

        # a registry hive in the evidence pile was invalid and the user chose not to skip
        except RegFiKeyError, e:
            self.handle_parse_error(e)

        # an invalid file was given for processing
        except RegAcquireError, e:
            self.handle_parse_error(e)
       
        except RegBadEvidenceError, e:
            self.handle_parse_error(e)      

        # everything added, lets do some forensics!
        else:
            # delete all our scratch files / databases
            #try:
            #self._removeall(os.path.join(self.directory, "registryfiles"))
            #except:
            #self.UI.msgBox("WARNING: Registry Decoder was unable to remove the scratch directory. New evidence cannot be added to this case unless you manually remove the 'registryfiles' directory in your case folder.")

            return True
    
        return False
    
    def handle_parse_error(self, e, caseinfo=None):
        # using print here is okay, this is a really bad error (we could not process a peice of evidence)
        # the GUI has already prompted the user and asked to skip the file or not
        print "error: %s" % str(e)
        traceback.print_exc(file=sys.stdout)    
        


