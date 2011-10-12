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
# contains all of the code for the case creation UI and event handlers

import os,sys,stat,time,shutil,traceback

from errorclasses import *

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *
import sqlite3

import start_processing
import GUI.guicommon as common

class caseInformation:

    def __init__(self):
        self.made_db = 0

    def case_str(self):

        headers = ("Case Name:","Case Number:","Investigator:","Case Comments:","Case Directory:")
        values  = (self.scasename, self.scasenumber, self.sinvestigator, self.scomments, self.directory)

        retstring = ""

        for i in xrange(len(headers)):
            retstring = retstring + "%-25s %s\n" % (headers[i],values[i])

        return retstring

    def create_casedb(self):
            
        dbname = "caseinfo.db"
        fulldb = os.path.join(self.directory, dbname)

        if self.made_db:
            # resetting the database with new values
            self.conn = None
            self.cursor = None
            os.unlink(fulldb)

        self.conn = sqlite3.connect(fulldb)

        self.cursor = self.conn.cursor()

        self.columns  = ["casename", "casenumber", "investigatorname", "comments", "casedirectory"]

        # build string to create table
        colstring = ''.join([x + " text," for x in self.columns])[:-1]

        self.cursor.execute("create table caseinformation (" + colstring +  ", id integer primary key asc)")            

        self.conn.commit()
        
        self.made_db = 1

    def check_directory(self, pass_check):

        ret = 0
        good = 0

        try:
            mode = os.stat(self.directory)[stat.ST_MODE]
            good = 1
        except:
            print "error: " , sys.exc_info()[1]
            QMessageBox.critical(self.gui, "Error", "Specified Directory Does not Exist")

        if good:
            if not mode & stat.S_IWUSR:
                QMessageBox.critical(self.gui,"Eror","Unable to write to specific directory")
            
            elif os.listdir(self.directory) and not pass_check:
                # ask the user if they are adding evidence to a new case
                # if not, error out
                # if, return 2
                ok = self.gui.yesNoDialog("Chosen directory already oontains files.", "Are you adding files to an existing case?")
                if ok:
                    ret = 2
                else:
                    QMessageBox.critical(self.gui,"Error","Non-empty directory specificied. Pleaes choose another.")
            else:
                ret = 1
            
        return ret

    def caseInformationButtonClicked(self, pass_check=0):
    
        self.scasename     = unicode(self.gui.casename.text())
        self.scasenumber   = unicode(self.gui.casenumber.text())
        self.sinvestigator = unicode(self.gui.investigatorname.text())
        self.scomments     = unicode(self.gui.comments.text())
        self.directory     = unicode(self.gui.caseDirectoryInput.text())
        self.directory     = self.directory.strip("\r\n\t")
            
        passed = self.check_directory(pass_check)

        # if the user is adding evidence to a new case
        self.gui.add_evidence = passed == 2

        # keep old investigator info is just adding evidence
        if pass_check or passed == 1:
    
            self.create_casedb()
        
            colstring = ''.join([x + "," for x in self.columns])[:-1]
        
            self.cursor.execute("insert into caseinformation (%s) values (?,?,?,?,?)"\
                 % colstring, (\
                self.scasename, \
                self.scasenumber,\
                self.sinvestigator,\
                self.scomments,\
                self.directory,
                ))

            self.conn.commit()
        
        if passed:
            
            self.gui.created_dir = self.directory

            if not pass_check:
                self.gui.evidenceTable.clearContents()  

            self.showAddEvidenceForm()
   
    def showAddEvidenceForm(self):
        self.gui.stackedWidget.setCurrentIndex(common.ADD_EVIDENCE)        

    def caseDirectoryInputClicked(self):

        # this will place the choosen filename into the label for the case info button handler to pick up
        directory = QFileDialog.getExistingDirectory(parent=self.gui, caption="Choose Case Save Directory")
        self.gui.caseDirectoryInput.setText(directory)
    
class addEvidence:

    def __init__(self):

        self.original_dir = ""
        self.last_dir = self.original_dir

        self.evidence_list = []

        self.setMyTableHeader()
    
    def evidence_str(self):

        ret = "Evidence List:\n"
        for filename in self.evidence_list:

            ret = ret + filename + "\n"

        return ret

    def addEvidenceButtonClicked(self):
        
        files = QFileDialog.getOpenFileNames(directory=self.last_dir, filter="All (*)", parent=self.gui, caption="Add Evidence Files (Registry Decoder Database, Raw Disk Image, Registry File)")

        filelist = files

        for filename in filelist:
        
            filename = unicode(filename.toUtf8())
    
            # update dir for subsequent adds
            if self.last_dir == self.original_dir:
                self.last_dir = os.path.abspath(filename)
        
            # remove any duplicate file name
            if filename not in self.evidence_list:
                self.evidence_list.append(filename)

        self.redrawListBox()

    def setMyTableHeader(self):    
    
        header_list = ["File Path", "Alias (Optional)"]
        
        self.gui.evidenceTable.setColumnCount(len(header_list))

        self.gui.evidenceTable.setHorizontalHeaderLabels(header_list)

        self.gui.evidenceTable.resizeColumnsToContents()
   
    def get_alias(self, row):

        alias_item = self.gui.evidenceTable.item(row, 1)

        if alias_item:
            alias = unicode(alias_item.text())
        else:
            alias = ""
    
        return alias

    def redrawListBox(self, selectedIndexes=[]):

        self.setMyTableHeader()
        
        numfiles = len(self.evidence_list)
        self.gui.evidenceTable.setRowCount(numfiles)

        # for each file
        for row in xrange(numfiles):

            filename = self.evidence_list[row]
            alias = self.get_alias(row)
            
            # set the row
            rowstringlist = [filename, alias]

            # add its row and column
            for column in xrange(len(rowstringlist)):

                val = rowstringlist[column]

                self.gui.evidenceTable.setItem(row, column, QTableWidgetItem(val))

        # stretch columns to show all data
        self.gui.evidenceTable.resizeColumnsToContents()
        self.gui.evidenceTable.resizeRowsToContents()

    def removeEvidenceButtonClicked(self):

        # get a sorted list of the rows to be removed
        selectedIndexes = [index.row() for index in self.gui.evidenceTable.selectedIndexes()]
        selectedIndexes.sort()

        ctr = 0

        for index in selectedIndexes:
    
            # remove from our list and delete from GUI    
            del self.evidence_list[index - ctr]
        
            self.gui.evidenceTable.removeRow(index - ctr)
        
            ctr = ctr + 1

    def doneEvidenceButtonClicked(self):

        self.gui.alias_hash = {}

        self.gui.acquire_current = self.gui.currentCheckBox.isChecked()
        self.gui.acquire_backups = self.gui.backupCheckBox.isChecked()

        # record aliases
        numfiles = len(self.evidence_list)

        if numfiles == 0:
            self.gui.msgBox("No evidence file(s) were added. Unable to process.")
            return

        for row in xrange(numfiles):
            filename = self.evidence_list[row]
            alias = self.get_alias(row)
            
            # will cry if this ever hits
            if filename in self.gui.alias_hash:
                raise RDError("BUG: duplicate file in alias hash %s" % filename)
            
            self.gui.alias_hash[filename] = alias

        self.gui.stackedWidget.setCurrentIndex(common.VIEW_SUMMARY)

class caseSummary:

    def __init__(self):
        pass


    def showSummary(self):

        summary_string = self.case_str() + self.evidence_str()
        self.gui.summaryLabel.setText(summary_string)

    def showProgress(self):

        self.gui.stackedWidget.setCurrentIndex(common.PROGRESS_LABEL)

    # http://code.activestate.com/recipes/193736-clean-up-a-directory-tree/
    def rmgeneric(self, path, __func__):

        __func__(path)
                
    def removeall(self, path):

        if not os.path.isdir(path):
            return
        
        files=os.listdir(path)

        for x in files:

            if x == "caseinfo.db":
                continue

            fullpath=os.path.join(path, x)
            if os.path.isfile(fullpath):
                f=os.remove
                self.rmgeneric(fullpath, f)
            elif os.path.isdir(fullpath):
                self.removeall(fullpath)
                f=os.rmdir
                self.rmgeneric(fullpath, f)

    def setupCaseDir(self):
            
        regdir = os.path.join(self.directory, "registryfiles")

        # this errors if the user added bad evidence and then redoes processing
        try:
            os.mkdir(regdir)
        except:
            # the case_obj stuff gets reinitalized after button is pressed
            if self.gui.add_evidence == 0:
                self.removeall(self.directory)
                os.mkdir(regdir)
        try:
            os.mkdir(os.path.join(regdir,"singlefiles"))
        except:
            pass

    def startProcessingButtonClicked(self):

        self.gui.progressLabel.setText(QString("Starting Processing.."))
        self.gui.update()
        self.gui.app.processEvents()
     
        # setup the case directory
        self.setupCaseDir()

        self.gui.stackedWidget.setCurrentIndex(common.PROGRESS_LABEL)
        self.gui.update()
        self.gui.repaint()
        self.gui.app.processEvents()

        # try to add the given evidence
        try:
            start_processing.case_processing().perform_processing(self)    

        # a registry hive in the evidence pile was invalid and the user chose not to skip
        except RegFiKeyError, e:
            self.handle_parse_error(e)

        # an invalid file was given for processing
        except RegAcquireError, e:
            self.handle_parse_error(e)
        
        # everything added, lets do some forensics!
        else:
            # delete all our scratch files / databases
            self.removeall(os.path.join(self.directory, "registryfiles"))
            self.gui.stackedWidget.setCurrentIndex(common.CASE_WINDOW)

    def handle_parse_error(self, e):
        print "error: %s" % str(e)
        traceback.print_exc(file=sys.stdout)

        
        self.caseInformationButtonClicked(1)
        self.gui.stackedWidget.setCurrentIndex(common.ADD_EVIDENCE)    
            
            
# first screen that pops up
class createcase(caseInformation, addEvidence, caseSummary):

    def __init__(self, gui):

        self.gui = gui

        caseInformation.__init__(self)
        addEvidence.__init__(self)
        caseSummary.__init__(self)

        self.connectSlots(gui)

    def connectSlots(self, gui_ref):

        # CASE_INFO
        self.gui.connect( gui_ref.caseInformationButton,   SIGNAL("clicked()"), self.caseInformationButtonClicked )
        self.gui.connect( gui_ref.BrowseCreateCase,        SIGNAL("clicked()"), self.caseDirectoryInputClicked )

        # add_evidence
        self.gui.connect( gui_ref.addEvidenceButton,       SIGNAL("clicked()"), self.addEvidenceButtonClicked )
        self.gui.connect( gui_ref.removeEvidenceButton,    SIGNAL("clicked()"), self.removeEvidenceButtonClicked )
        self.gui.connect( gui_ref.doneEvidenceButton,      SIGNAL("clicked()"), self.doneEvidenceButtonClicked )

        # view_summary
        self.gui.connect( gui_ref.backToAddEvidenceButton, SIGNAL("clicked()"), self.showAddEvidenceForm )
        self.gui.connect( gui_ref.startProcessingButton,   SIGNAL("clicked()"), self.startProcessingButtonClicked )



    
