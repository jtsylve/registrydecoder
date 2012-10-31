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

guidrawn = 0

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

import sqlite3, zipfile, sys, os

import interfaces.GUI.generate_forms as gf
from interfaces.GUI.uifiles.registrydecoder_ui import Ui_registrydecoder

from interfaces.GUI.createcase import createcase
from interfaces.GUI.filetab import filetab
from interfaces.GUI.plugintab import plugintab
from interfaces.GUI.searchtab import searchtab
from interfaces.GUI.timelinetab import timelinetab
from interfaces.GUI.pathtab import pathtab

import interfaces.GUI.guicommon as gcommon
import interfaces.GUI.reportactions as reportactions

import registrydecoder.registrydecoder as registrydecoder

import interfaces.GUI.screen_display as screen_display

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
        directory = QFileDialog.getExistingDirectory(parent=self.gui, directory="/root/tmpcasedir", caption="Choose Case Directory")    
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
            self.gui._set_case_info(directory)

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
    
class registryDecoderGUI(QMainWindow, Ui_registrydecoder, reportactions.reportactions):
    
    def reset_gui(self):
        if self.case_obj:
            self.case_obj.current_fileid = -42

    def __init__(self, app, parent =  None):
        self.case_obj = None

        self.RD = registrydecoder.registrydecoder(self)

        self.report_obj = screen_display

        self.reset_gui()

        # setup GUI nonsense
        QMainWindow.__init__(self, parent)
        Ui_registrydecoder.__init__(self)
        self.setupUi(self)
        self.app = app

        gcommon.parse_cmdline(self, sys.argv) 

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
 
    def generate_search_results_tab(self, sp, sr, fileid, color_idxs=[]):
        return self.searchtab.generate_results_tab(sp, sr, fileid, color_idxs)
    
    def generate_plugin_results_tab(self, result):
        return self.plugintab.generate_plugin_results_tab(result) 

    def generate_path_results_tab(self, sp, results, fileid):
        return self.pathtab.generate_path_results_tab(sp, results, fileid)

    def _set_case_info(self, directory):
        o = self.RD.opencase
        o.opencase(directory)
        self.case_obj = o
    
        self.RD = registrydecoder.registrydecoder(self)
        
        self.directory = directory
        
        self.stackedWidget.setCurrentIndex(gcommon.CASE_WINDOW)
     
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
            if not hasattr(self, "case_obj") or self.case_obj == None:
                self._set_case_info(self.createcase.directory)

            # Add the tempalte api to each
            for tab in self.analysis_tabs:
                tab.gcommon = gcommon
                tab.gf   = gf.generate_forms(self)

            # ....
            # export menu
            self.connect( self.actionExport_Plugins, SIGNAL("triggered(bool)"),  self.saveAllPlugins) 
            self.connect( self.actionExport_Searches, SIGNAL("triggered(bool)"), self.saveAllSearches)
            self.connect( self.actionExport_Paths, SIGNAL("triggered(bool)"),     self.saveAllPaths)
            self.connect( self.actionExport_Plugins_and_Searches, SIGNAL("triggered(bool)"), self.savePluginsSearches)

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
        elif hasattr(closed_tab, "is_bulk") or hasattr(closed_tab, "diff_tab"):
            remove = 1

        if remove == 1: 
            self.analysisTabWidget.removeTab(index)
        else:
            print "Canot close tab: %s" % str(self.analysis_tabs)

    def ctrlw_tab(self):
        index = self.analysisTabWidget.currentIndex()
        self.handleAnalysisTabClose(index)

    def updateLabel(self, message):
        self.progressLabel.setText(QString(message))
        self.update()
        self.app.processEvents()
        
    def msgBox(self, message, warn=1):

        if warn:
            qb = gcommon.RDMessageBox(self.app, message)
        else:
            qb = gcommon.RDMessageBoxInfo(self.app, message)

        qb.show()

    # gets the active fileIDs from the tree of 'action'
    def get_current_fileids(self, action, max=-1):
        treeWidgets = { "search"       : ["searchTreeWidget"],
                        "diff_search"  : ["searchTreeWidget", "searchDiffTreeWidget"],
                        "plugins"      : ["pluginFilestreeWidget"],
                        "diff_plugins" : ["pluginFilestreeWidget", "pluginDiffTreeWidget"],
                        "timeline"     : ["timelineTreeWidget"],
                        "path"         : ["pathAnalysisTreeWidget"],
                        "filebrowser"  : ["fileTreeWidget"],
                      }
       
        widget_names = treeWidgets[action]
        ret = []

        for widget_name in widget_names:
            ret = ret + gcommon.get_file_ids(self, widget_name, max)

        return ret

    def get_registry_path_from_user(self):
        return QInputDialog.getText(self, "Please Enter the Registry Path", "Path:")

    def fill_info(self, tab):
        active_tabs = tab.analysis_tab.active_tabs

        if active_tabs != None:
            # set all the info about the specific tab...
            active_tabs[tab] = tab.info_class

    # gets info from GUI on what to put into file-based report
    # we allow limiting by selecting rows
    # we overwrite the tempalte manager values for the tab
    # this allows the user to deleted/sort/move columns/etc and have it show in the report the same
    def get_report_info_from_tab(self, tab_widget):
        data = []
        headers = []
      
        try: 
            tab_info = tab_widget.analysis_tab.active_tabs[tab_widget]
        except:
            return None

        tm = tab_info.tm
        tm.report_data = data
        tm.headers     = headers        

        tbl = tab_widget.tblWidget

        rcount = tbl.rowCount()
        ccount = tbl.columnCount()

        # keeps track of where we are in the data list
        didx = 0

        # limit to users selections
        selected_rows = []    
        selected = tbl.selectedIndexes()
        selectonly = len(selected) > 0
        for index in selected:
            selected_rows.append(index.row())

        if tm.headers != []:
            for c in xrange(0, ccount):
                item = tbl.horizontalHeaderItem(c) 
                if item:
                    headers.append(unicode(item.text()))

        for row in xrange(0, rcount):
            # if the user chose specific items then only report them
            if selectonly and not row in selected_rows:
                continue
            
            data.append([]) 

            for col in xrange(0, ccount):
                t = tbl.item(row, col)
        
                if t:
                    val = unicode(t.text())
                else:
                    val = unicode("")

                data[didx].append(val)

            didx = didx + 1

        # get the variables needed for the reporting modules
        return tm

def do_error_msg(message):
    global guidrawn

    if guidrawn:
        errorbox = QMessageBox()
        errorbox.setText(str(message))
        errorbox.exec_()
    else:
        print "Unable to create error message box. Error must have been hit early on. Please see registry-decoder-error.txt for more information"
        
def do_gui_main():

    global guidrawn

    app    = QApplication(sys.argv)

    window = registryDecoderGUI(app)

    guidrawn = 1

    window.showMaximized()

    app.exec_()






