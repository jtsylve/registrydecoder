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
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

import datetime

class searchtab:
    def __init__(self, gui):
        self.name = "Search Tab"
        self.active_tabs = {}

        self.gui = gui

        self.act_handlers = {}

    def draw(self):
        self.fileinfo_hash = self.gcommon.fill_tree(self.gui, "searchTreeWidget")     

    def search_terms_file_browse(self):    
        filename = QFileDialog.getOpenFileName(directory="/home/x/", filter="All (*)", parent=self.gui, caption="Add Search Terms (newline seperated))")            
        
        self.gui.searchTermsLineEdit.setText(filename)

    def _boxIsChecked(self, boxName):
        return self.gui.__getattribute__(boxName).isChecked()

    def _get_search_params_boxes(self):
        return [self._boxIsChecked("searchKeysCheckBox"), self._boxIsChecked("searchNamesCheckBox"), self._boxIsChecked("searchDataCheckBox")]
    
    def _get_search_single(self, place="search"):
        edit = self.gui.__getattribute__("%sLineEdit" % place)
        searchterm = unicode(edit.text())

        return searchterm

    def _get_search_file(self, place="search"):
        lineedit =  self.gui.__getattribute__("%sTermsLineEdit" % place)
        filename = unicode(lineedit.text())

        return filename 
    
    def _set_search_params(self):
        (search_term, search_file)  = (self._get_search_single(), self._get_search_file())

        partial_search  = self._boxIsChecked("partialSearchRadioButton")

        (search_keys, search_names, search_values) = self._get_search_params_boxes()

        start_date    = str(self.gui.searchStartDateLineEdit.text())
        end_date      = str(self.gui.searchEndDateLlineEdit.text())
   
        return self.gui.RD.search.set_search_params(search_term, search_file, partial_search, search_keys, search_names, search_values, start_date, end_date)
                 
    def _do_gen_tab(self, sp, sr, fileid, is_diff=0):
        h = self._get_tab_text(sp.searchterm, is_diff)
        l = self._get_label_text(sp.searchterm, sr.filepath)

        return self.gf.generate_search_view_form(self, fileid, h, l, sr.results, is_diff)

    # genereates a search result tab and fills the GUI table
    def generate_results_tab(self, sp, sr, fileid, color_idxs=[]):
        tab = self._do_gen_tab(sp, sr, fileid)
        
        self._setup_menu(tab.searchResTable)        
        
        return tab

    def _setup_menu(self, widget):
        self.act_handlers[widget] = self.gcommon.action_handler(self, widget, "Switch to File View", 1, 1)

        self.act_handlers[widget].setup_menu()        

    # called when 'search' is clicked
    def viewTree(self):
        sp = self._set_search_params()

        if not sp or sp == None:
            return

        perform_diff = self.gui.performSearchDiffCheckBox.isChecked()

        search_results = self.gui.RD.search.perform_search(sp, perform_diff)
 
        self.gui.RD.search.write_search_results(search_results) 
        
        self.gui.reset_gui()

    def handle_search_delete(self, event):
        curtab = self.gui.analysisTabWidget.currentWidget()
        
        self.gui.case_obj.current_fileid = curtab.fileid
        
        table  = curtab.searchResTable

        if event.key() == Qt.Key_Delete:
            self.remove_search_result(curtab, table)
        
        return QTableWidget.keyPressEvent(table, event)

    def remove_search_result(self, curtab, table):
        row = table.currentRow()        
        table.removeRow(row)       

    def createReportClicked(self): 
        self.gui.createReportClicked("Search Single")
    
    def diffBoxClicked(self, isChecked):
        self.gcommon.diffBoxClicked(self, isChecked, "searchDiffTreeWidget")

    def _get_label_text(self, searchterm, filepath):
        return "Results for searching %s against %s" % (searchterm, filepath)

    def _get_tab_text(self, searchterm, is_diff):
        if is_diff:
            ret = "Diff: "
        else:
            ret = ""

        return ret + "Search Results - %s" % searchterm
     
