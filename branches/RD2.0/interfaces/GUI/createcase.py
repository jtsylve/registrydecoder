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

import os

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

import interfaces.GUI.guicommon as common

class caseInformation:
    def __init__(self, gui):
        self.gui = gui

    def caseInformationButtonClicked(self, pass_check=0):
        self.scasename     = unicode(self.gui.casename.text())
        self.scasenumber   = unicode(self.gui.casenumber.text())
        self.sinvestigator = unicode(self.gui.investigatorname.text())
        self.scomments     = unicode(self.gui.comments.text())
        self.directory     = unicode(self.gui.caseDirectoryInput.text())
        self.directory     = self.directory.strip("\r\n\t")
       
        caseinfo = self.gui.RD.createcase.set_case_info(self.scasename, self.scasenumber, self.sinvestigator, self.scomments, self.directory)
        passed = self.gui.RD.createcase.processCaseInfo(caseinfo, pass_check)

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
    def __init__(self, gui):
        self.original_dir = ""
        self.last_dir = self.original_dir
        self.gui = gui

        self.gui.evidence_list = []

        self.setMyTableHeader()
    
    def evidence_str(self):
        ret = "Evidence List:\n"
        for filename in self.gui.evidence_list:
            ret = ret + filename + "\n"

        return ret

    def addEvidenceButtonClicked(self):
        filelist = QFileDialog.getOpenFileNames(directory=self.last_dir, filter="All (*)", parent=self.gui, caption="Add Evidence Files (Registry Decoder Database, Raw Disk Image, Registry File)")

        for filename in filelist:
        
            filename = unicode(filename.toUtf8())
    
            # update dir for subsequent adds
            if self.last_dir == self.original_dir:
                self.last_dir = os.path.abspath(filename)
        
            # remove any duplicate file name
            if filename not in self.gui.evidence_list:
                self.gui.evidence_list.append(filename)

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
        
        numfiles = len(self.gui.evidence_list)
        self.gui.evidenceTable.setRowCount(numfiles)

        # for each file
        for row in xrange(numfiles):

            filename = self.gui.evidence_list[row]
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
            del self.gui.evidence_list[index - ctr]
        
            self.gui.evidenceTable.removeRow(index - ctr)
        
            ctr = ctr + 1

    def doneEvidenceButtonClicked(self):
        self.gui.alias_hash = {}

        self.gui.acquire_current = self.gui.currentCheckBox.isChecked()
        self.gui.acquire_backups = self.gui.backupCheckBox.isChecked()

        # record aliases
        numfiles = len(self.gui.evidence_list)

        if numfiles == 0:
            self.gui.msgBox("No evidence file(s) were added. Unable to process.")
            return

        for row in xrange(numfiles):
            filename = self.gui.evidence_list[row]
            alias = self.get_alias(row)
            
            # will cry if this ever hits
            if filename in self.gui.alias_hash:
                raise RDError("BUG: duplicate file in alias hash %s" % filename)
            
            self.gui.alias_hash[filename] = alias

        self.gui.stackedWidget.setCurrentIndex(common.VIEW_SUMMARY)

class create_case:
    def __init__(self, gui):
        self.gui = gui

    def _case_str(self):
        headers = ("Case Name", "Case Number", "Investigator", "Case Comments", "Case Directory")
        values  = (self.scasename, self.scasenumber, self.sinvestigator, self.scomments, self.directory)

        retstring = ""

        for i in xrange(len(headers)):
            retstring = retstring + "%-25s: %s\n" % (headers[i],values[i])

        return retstring

    def showSummary(self):
        summary_string = self._case_str() + self.evidence_str()
        self.gui.summaryLabel.setText(summary_string)

    def showProgress(self):
        self.gui.stackedWidget.setCurrentIndex(common.PROGRESS_LABEL)

    def updateGUI(self):
        self.gui.update()
        self.gui.repaint()
        self.gui.app.processEvents()

    def startProcessingButtonClicked(self):
        self.gui.progressLabel.setText(QString("Starting Processing.."))
     
        # setup the case directory, bail if errors found
        if self.gui.RD.createcase.setupCaseDir() == 0:
            return

        self.gui.stackedWidget.setCurrentIndex(common.PROGRESS_LABEL)
       
        succesful = self.gui.RD.createcase.process_case_files()        

        if succesful: 
            self.gui.stackedWidget.setCurrentIndex(common.CASE_WINDOW)
        else:
            self.handle_parse_error()
         
    def handle_parse_error(self):
        self.caseInformationButtonClicked(1)
        self.gui.stackedWidget.setCurrentIndex(common.ADD_EVIDENCE)    
            
# first screen that pops up
class createcase(caseInformation, addEvidence, create_case):
    def __init__(self, gui):
        self.gui = gui

        create_case.__init__(self, gui)
        caseInformation.__init__(self, gui)
        addEvidence.__init__(self, gui)

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



    
