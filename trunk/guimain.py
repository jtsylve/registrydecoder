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

import sys, os

# If we're in a pyinstaller executable, from volatility
if hasattr(sys, "frozen"):
    try:
        import iu, _mountzlib
        mei = os.path.abspath(os.environ["_MEIPASS2"])
        sys.path.append(mei)
        os.environ['PATH'] = mei + ";" + os.environ['PATH']
    except ImportError:
        pass

profile = 0

import stat, time, cStringIO
import traceback

from errorclasses import *

guidrawn = 0

# taken from ERIC IDE since QT does not throw exceptions internally
def excepthook(excType, excValue, tracebackobj):

    if excType == MsgBoxError:
        errorbox = QMessageBox()
        errorbox.setWindowTitle(str("Registry Decoder"))
        errorbox.setText(str(excValue))
        errorbox.exec_()
        return
 
    dirname = os.getcwd()
    logfilename = os.path.join(dirname, "registry-decoder-error.txt")

    separator = "-" * 80

    notice = "An error has occurred and the details have been written to %s. Please send this file to registrydecoder@digdeeply.com so that we may address the issue." % (logfilename)
    
    timeString = time.strftime("%Y-%m-%d, %H:%M:%S")
        
    tbinfofile = cStringIO.StringIO()
    traceback.print_tb(tracebackobj, None, tbinfofile)
    tbinfofile.seek(0)
    tbinfo = tbinfofile.read()

    errmsg = '%s: \n%s' % (str(excType), str(excValue))

    sections = [separator, timeString, separator, errmsg, separator, tbinfo]

    msg = '\n'.join(sections)
    try:
        logfile = open(logfilename, "a+")
        logfile.write(msg)
        logfile.close()

    except IOError:
        pass

    if guidrawn:
        errorbox = QMessageBox()
        errorbox.setText(str(notice))
        errorbox.exec_()
    else:
        print "Unable to create error message box. Error must have been hit early on. Please see registry-decoder-error.txt for more information"
        
    sys.exit(1)

sys.excepthook = excepthook

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *
import sqlite3, zipfile

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from xlwt import Workbook


import templates.util.util as tutil
import template_manager as tmmod 
import report_manager as rpmod 
import GUI.generate_forms as gf
import GUI.reportfuncs as rf

from GUI.uifiles.registrydecoder_ui import Ui_registrydecoder
from GUI.createcase import createcase
from GUI.filetab import filetab
from GUI.plugintab import plugintab
from GUI.searchtab import searchtab
from GUI.timelinetab import timelinetab
from GUI.reportfuncs import report_handler
from GUI.pathtab import pathtab

import GUI.guicommon as gcommon

import opencase, common

class objclass:
    pass

class start_page:

    def __init__(self, gui):

        self.gui = gui
        self.connectSlots()

    def connectSlots(self):

        self.gui.connect( self.gui.startPageButton, SIGNAL("clicked()"), self.startPageButtonClicked )

    def startPageButtonClicked(self):
        
        if self.gui.startnewcase.isChecked():
            self.gui.stackedWidget.setCurrentIndex(gcommon.CASE_INFO)
        else:
            self.gui.stackedWidget.setCurrentIndex(gcommon.LOAD_CASE)

class load_case:

    def __init__(self, gui):

        self.gui = gui
        self.connectSlots()

    def connectSlots(self):

        self.gui.connect( self.gui.browseCaseButton, SIGNAL("clicked()"), self.browseCaseButtonClicked )
        self.gui.connect( self.gui.loadCaseButton,   SIGNAL("clicked()"), self.loadCaseButtonClicked )

    def browseCaseButtonClicked(self):
        directory = QFileDialog.getExistingDirectory(parent=self.gui, directory="/home/x/projects/regdecoder/trunk/src/casefolder", caption="Choose Case Directory")    
        self.gui.caseFolderInput.setText(directory)
    
    def loadCaseButtonClicked(self):
        directory     =  unicode(self.gui.caseFolderInput.text())
        directory     = directory.strip("\r\n\t")

        check_file = os.path.join(directory,"caseobj.pickle")

        try:
            os.stat(check_file)
            good = 1
        except:
            good = 0
            QMessageBox.critical(self.gui, "Error", "Specified Directory is not a Registry Decoder Case Folder")

        if good:
            set_case_info(directory, self)

def set_case_info(directory, obj):

    o = opencase.opencase(directory)

    if hasattr(obj, "gui"):
        gui = obj.gui
    else:
        gui = obj

    gui.case_obj  = o
    gui.directory = directory
    gui.stackedWidget.setCurrentIndex(gcommon.CASE_WINDOW)
        
# implements file menu handlings
class file_menu:

    def __init__(self, gui):

        self.gui = gui
        self.connectSlots()

    def connectSlots(self):
        
        self.gui.connect( self.gui.actionBackup_Case, SIGNAL("triggered(bool)"), self.backupCaseClicked )
        self.gui.connect( self.gui.actionExit, SIGNAL("triggered(bool)"), self.gui.app, SLOT('quit()') )
        self.gui.connect( self.gui.actionClose_Case_2, SIGNAL("triggered(bool)"), self.closeCaseClicked )

    def closeCaseClicked(self):

        attrs = ["case_obj", "directory", "alias_hash", "created_dir", "acquire_current", "acquire_backups", "add_evidence", "plugin_dirs"]
       
        for attr in attrs:
            if hasattr(self.gui, attr):
                delattr(self.gui, attr)

        self.gui.stackedWidget.setCurrentIndex(gcommon.START_PAGE)

    def backupCaseClicked(self):

        if hasattr(self.gui, "directory"):
            self.do_backup(self.gui.directory)            
        else:
            self.gui.msgBox("Backup Case called from invalid context")  

    def do_backup(self, directory):

        zipname = QFileDialog.getSaveFileName(parent=self.gui, caption="Choose A Save File (zip)")

        zipname = str(zipname)

        if len(zipname) == 0:
            self.gui.msgBox("No filename was given for backup. Cannot Proceed.")
            return

        if not zipname.endswith(".zip"):
            zipname = zipname + ".zip"

        self.create_zip(directory, "RDbackup", zipname)
        
        self.gui.msgBox("Backup successfully created.")

    # stack overflow recipe
    def zipfolder(self, path, relname, archive):
        
        paths = os.listdir(path)
        
        for p in paths:
            p1 = os.path.join(path, p) 
            p2 = os.path.join(relname, p)
        
            if os.path.isdir(p1): 
                self.zipfolder(p1, p2, archive)
            else:
                archive.write(p1, p2) 

    def create_zip(self, path, relname, archname):
        
        archive = zipfile.ZipFile(archname, "w", zipfile.ZIP_DEFLATED)
        
        if os.path.isdir(path):
            self.zipfolder(path, relname, archive)
        else:
            archive.write(path, relname)
        
        archive.close()
    
class registryDecoderGUI(QMainWindow, Ui_registrydecoder):

    def __init__(self, app, parent =  None):
        
        # setup GUI nonsense
        QMainWindow.__init__(self, parent)
        Ui_registrydecoder.__init__(self)
        self.setupUi(self)
        self.app = app

        common.parse_cmdline(self, sys.argv) 

        # for now, just to register all the slots
        self.createcase = createcase(self)
        self.start_page = start_page(self)
        self.load_case  = load_case(self)
        self.file_menu  = file_menu(self)

        # back buttons
        self.connect (self.goBackPushButton, SIGNAL("clicked()"), self.resetForm )
        self.connect (self.goBackPushButton2, SIGNAL("clicked()"), self.resetForm )

        # overall page changing
        self.connect( self.stackedWidget, SIGNAL("currentChanged(int)"), self.checkStackChange )

        # case analysis tabs changing
        self.connect( self.analysisTabWidget, SIGNAL("currentChanged(int)"), self.handleAnalysisTabChange )
        self.connect( self.analysisTabWidget, SIGNAL("tabCloseRequested(int)"), self.handleAnalysisTabClose ),

        # add plugin tab and connect signals        
        self.plugintab = plugintab(self)
        self.connect( self.hiveComboBox,    SIGNAL("activated(int)"), self.plugintab.update_hive)
        self.connect( self.runPluginButton, SIGNAL("clicked()"), self.plugintab.run_plugin)
        self.connect( self.pluginDiffCheckBox, SIGNAL("clicked(bool)"), self.plugintab.diffBoxClicked)
        self.pluginDiffTreeWidget.hide()

        # file tab
        self.filetab = filetab(self)
        self.connect( self.treeViewPushButton, SIGNAL("clicked()"), self.filetab.viewTree)   
 
        # search tab
        self.searchtab = searchtab(self)
        self.connect( self.searchPushButton, SIGNAL("clicked()"), self.searchtab.viewTree)
        self.connect( self.searchTermsPushButton, SIGNAL("clicked()"), self.searchtab.search_terms_file_browse)
        self.connect( self.performSearchDiffCheckBox, SIGNAL("clicked(bool)"), self.searchtab.diffBoxClicked)      
        
        self.searchDiffTreeWidget.hide()       

        # pathtab
        self.pathtab = pathtab(self)
        self.connect( self.pathPushButton, SIGNAL("clicked()"), self.pathtab.viewTree)
        self.connect( self.pathTermsPushButton, SIGNAL("clicked()"), self.pathtab.path_terms_file_browse)
 
        # timelinetab
        self.timelinetab = timelinetab(self)
        self.connect( self.timelinePushButton, SIGNAL("clicked()"), self.timelinetab.viewTree)
        self.connect( self.timelineFilePushButton, SIGNAL("clicked()"), self.timelinetab.timeline_output_browse)

        self.file_drawn   = 0
        self.plugin_drawn = 0
        self.search_drawn = 0
        self.path_drawn   = 0
        self.timeline_drawn = 0

        self.analysis_tabs = [self.filetab, self.plugintab, self.searchtab, self.pathtab, self.timelinetab]

    def resetForm(self):
    
        # called when the back button is hit on load case or new case, resets to the load page
        self.stackedWidget.setCurrentIndex(0)

    def yesNoDialog(self, message, message1):

        mbox = QMessageBox()
        mbox.setStandardButtons(QMessageBox.Yes|QMessageBox.No)
        mbox.setText(QString(message))
        mbox.setInformativeText(QString(message1))
        mbox.setDefaultButton(QMessageBox.No)
        answer = mbox.exec_()

        if answer == QMessageBox.Yes:
            ret = True            
        elif answer == QMessageBox.No:
            ret = False

        return ret

    def clearTrees(self):

        trees = [self.fileTreeWidget, self.searchTreeWidget, self.searchDiffTreeWidget, self.pluginFilestreeWidget, self.pluginDiffTreeWidget]
       
        for tree in trees:
            tree.clear() 

    # called when pages change
    def checkStackChange(self, index):

        if index == gcommon.VIEW_SUMMARY:
            self.createcase.showSummary()

        elif index == gcommon.CASE_WINDOW:

            # stuff to get case analysis rolling..
            self.clearTrees()

            # When the tab swtiches after case creation
            if not hasattr(self, "case_obj"):
                set_case_info(self.created_dir, self)

            # Add the tempalte api to each
            for tab in self.analysis_tabs:

                tab.tapi = tutil.templateutil(self.case_obj) 
                tab.tm   = tmmod.TemplateManager()
                tab.rm   = rpmod.report_manager(self)
                tab.gf   = gf.generate_forms(self)
                tab.rh   = rf.report_handler(self, tab.active_tabs, tab.rm, tab.gf)
                tab.gcommon = gcommon

            # ....
            # export menu
            self.connect( self.actionExport_Plugins, SIGNAL("triggered(bool)"), self.plugintab.rh.saveAllPlugins) 
            self.connect( self.actionExport_Searches, SIGNAL("triggered(bool)"), self.searchtab.rh.saveAllSearches)
            self.connect( self.actionExport_Paths, SIGNAL("triggered(bool)"), self.searchtab.rh.saveAllPaths)
            self.connect( self.actionExport_Plugins_and_Searches, SIGNAL("triggered(bool)"), self.searchtab.rh.savePluginsSearches)

            self.file_drawn = 1
            self.filetab.draw()

    # called when the user switches between analysis tabs
    def handleAnalysisTabChange(self, index):

        widget = self.analysisTabWidget.widget(index)
        text   = self.analysisTabWidget.tabText(index)

        if text == "File View":

            # initial loading of case
            if not self.file_drawn:
                self.filetab.draw()
                self.file_drawn = 1

        elif text == "Plugins":

            if not self.plugin_drawn:
                self.plugintab.draw()
                self.plugin_drawn = 1
        
        elif text == "Search":
            
            if not self.search_drawn:
                self.searchtab.draw()
                self.search_drawn = 1

        elif text == "Path Analysis":

            if not self.path_drawn:
                self.pathtab.draw()
                self.path_drawn = 1

        elif text == "Timeline":
    
            if not self.timeline_drawn:
                self.timelinetab.draw()
                self.timeline_drawn = 1
 
        # some dynamic tabs need this
        elif hasattr(widget, "fileid"):
            self.case_obj.current_fileid = widget.fileid 
            
        # BEFORE RELEASE - remove
        else:
            print "unknown column?? %s" % text
       
    def get_report_name(self, event):

        widget = self.analysisTabWidget.currentWidget()
 
        filename = QFileDialog.getSaveFileName(parent=self, caption="Choose Report Filename")

        widget.reportname.setText(filename)

    # closes any of the auto generated tabs
    # and removes them from the plugin that generated it
    def close_auto_tab(self, closed_tab):

        ret = False

        # check to see if the tab is auto generated from one of the
        # analysis tabs
        for auto_tab in self.analysis_tabs:
            
            if closed_tab in auto_tab.active_tabs:
               
                # this will be a no-op for most tabs
                if hasattr(auto_tab, "close_tab"):
                    auto_tab.close_tab(closed_tab)

                del auto_tab.active_tabs[closed_tab]

                ret = True
         
        return ret

    # called when a tab is closed in the analysis page
    # we currently dont allow users to close 'core' tabs  
    def handleAnalysisTabClose(self, index):

        closed_tab = self.analysisTabWidget.widget(index) 
   
        remove = 0

        # auto genned tabs
        if self.close_auto_tab(closed_tab): 
            remove = 1
                
        # bulk export tabs
        elif hasattr(closed_tab, "is_bulk"):
            remove = 1

        if remove == 1: 
            self.analysisTabWidget.removeTab(index)
        else:
            print "Canot close tab: %s" % str(self.analysis_tabs)

    def ctrlw_tab(self):

        index = self.analysisTabWidget.currentIndex()
        self.handleAnalysisTabClose(index)
        
    def msgBox(self, message, warn=1):

        if warn:
            qb = gcommon.RDMessageBox(self.app, message)
        else:
            qb = gcommon.RDMessageBoxInfo(self.app, message)

        qb.show()

def do_main():

    global guidrawn

    app    = QApplication(sys.argv)

    window = registryDecoderGUI(app)

    guidrawn = 1

    window.showMaximized()

    app.exec_()

def main():
    
    if profile:
        import cProfile
        cProfile.run('do_main()')
    else:
        do_main()

if __name__ == "__main__":
    main()
   

