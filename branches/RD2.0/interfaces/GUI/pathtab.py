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

class pathtab:
    def __init__(self, gui):
        self.name = "Path Tab"
        self.active_tabs = {}
        self.gui = gui

    def draw(self):
        self.fileinfo_hash = self.gcommon.fill_tree(self.gui, "pathAnalysisTreeWidget")     

    def path_terms_file_browse(self):    
        filename = QFileDialog.getOpenFileName(directory="/home/x/", filter="All (*)", parent=self.gui, caption="Add Paths (newline seperated))")            
        self.gui.pathTermsLineEdit.setText(filename)

    def _get_label_text(self, searchterm, filepath):
        return "Results for looking up path %s against %s" % (searchterm, filepath)

    def _get_tab_text(self, searchterm):
        return "Path Results - %s" % searchterm

    def generate_path_results_tab(self, sp, sr, fileid):
        h = self._get_tab_text(sp.pathterms)
        l = self._get_label_text(sp.pathterms, sr.filepath)

        return self.gf.path_export_form(self, fileid, h, l)

    def _get_path_single(self):
        return str(self.gui.pathLineEdit.text())

    def _get_path_file(self):
        return str(self.gui.pathTermsLineEdit.text())     

    def _set_path_params(self):
        (pathterms, pathsfile) = (self._get_path_single(), self._get_path_file())

        startDate    = str(self.gui.pathStartDateLineEdit.text())
        endDate      = str(self.gui.pathEndDateLlineEdit.text())
 
        includeVals  = self.gui.pathValuesCheckBox.isChecked() 

        return self.gui.RD.pathbased.set_analysis_params(pathterms, pathsfile, includeVals, startDate, endDate)

    # called when 'search' is clicked
    def viewTree(self):
        sp = self._set_path_params()

        if not sp:
            return

        results = self.gui.RD.pathbased.run_path_analysis(sp)

        self.gui.RD.pathbased.write_path_results(results)

        self.gui.reset_gui() 

    def createReportClicked(self): 
        self.gui.createReportClicked("Path Analysis Single")
    

