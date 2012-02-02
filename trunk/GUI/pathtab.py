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
from errorclasses import *

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

import datetime

class tmclass:
       
    def __init__(self, report_vals):
 
        self.plugin_set_header = 0
        self.timestamp         = None       
        self.report_data       = report_vals 
 
class key_info:

    def __init__(self, node, vals):
       
        self.node = node
        self.vals = vals 

class path_params:

    def __init__(self, pathterms, pathsfile, includeVals, startDate, endDate):
        
        self.pathterms   = pathterms
        self.pathsfile   = pathsfile
        self.includeVals = includeVals
        self.startDate   = startDate
        self.endDate     = endDate

class pathtab:

    def __init__(self, gui):
        self.name = "Path Tab"
        self.active_tabs = {}

        self.gui = gui

    def draw(self):
        self.pathinfo_hash = self.gcommon.fill_tree(self.gui, "pathAnalysisTreeWidget")  

    def path_terms_file_browse(self):    
        filename = QFileDialog.getOpenFileName(directory="/home/x/", filter="All (*)", parent=self.gui, caption="Add Paths (newline seperated))")            
        
        self.gui.pathTermsLineEdit.setText(filename)

    # returns None if patterm isn't a path in the current file
    def get_path_hits(self, pathterm, includeVals):

        node = self.gcommon.get_tree_node(self, pathterm)

        if not node:
            return None  
         
        if includeVals:
            # tuple of (name, data, raw data)
            vals = self.tapi.reg_get_values(node)
        else:
            vals = []                 

        return [key_info(node, vals)]

    # get results for the given search term(s) and fileid
    def handle_run_path_lookup(self, sp, fileid):

        results = []

        # run over all the searchterms in the same file
        for pathterm in sp.pathterms:
            hit = self.get_path_hits(pathterm, sp.includeVals)
            if hit:
                results = results + hit

        # if the user gave a search terms file
        if sp.pathsfile != "":
            sp.searchterm = "from %s" % sp.pathsfile
        # from the input box
        else:
            sp.searchterm = sp.pathterms[0]

        # remove results that break on the user date filtering
        if len(results) and (sp.startDate or sp.endDate):
            results = self.gcommon.filter_results(self, results, fileid, sp.startDate, sp.endDate)

        return results

    def do_run_path_lookup(self, fileid, sp):
    
        (filepath, evi_file, group_name) = self.gcommon.get_file_info(self.pathinfo_hash, fileid)

        self.gui.case_obj.current_fileid = fileid

        # results for fileid
        results = self.handle_run_path_lookup(sp, fileid)

        return self.gcommon.search_results(filepath, evi_file, group_name, results, fileid)

    def get_label_text(self, searchterm, filepath):

        return "Results for looking up path %s against %s" % (searchterm, filepath)

    def get_tab_text(self, searchterm):

        return "Path Results - %s" % searchterm

    def do_gen_tab(self, sp, sr, fileid):

        h = self.get_tab_text(sp.searchterm)
        l = self.get_label_text(sp.searchterm, sr.filepath)

        return self.gf.path_export_form(self, fileid, h, l) # sr.results

    # results is a list of key_info
    def get_report_vals(self, results, fileid):

        ret = []

        for row in xrange(len(results)):

            r = results[row]

            lastwrite = r.node.timestamps[fileid]
            lastwrite = datetime.datetime.fromtimestamp(lastwrite).strftime('%Y/%m/%d %H:%M:%S')

            # add the path and its last write time
            ret.append([self.tapi.full_path_node_to_root(r.node), lastwrite])

            # add any values
            for val_ent in r.vals:
                (name, val, rval) = val_ent
                ret.append(["", name, val])

        return ret   

    # genereates a search result tab and fills the GUI table
    def generate_tab(self, sp, sr, fileid):

        tab = self.do_gen_tab(sp, sr, fileid)

        report_vals = self.get_report_vals(sr.results, fileid)

        self.insert_results(tab, report_vals, sp.searchterm, fileid)
        
        return tab

    # performs the work for a path lookup
    # return of None means error
    # return of [] means no search matches
    def run_path_lookup(self, sp):

        gen_tab = 0

        all_results = self.gcommon.run_cb_on_tree(self, self.do_run_path_lookup, sp, "pathAnalysisTreeWidget")

        if all_results == None:
            return

        for results in all_results:

            # generate tab if they are there
            if len(results.results) > 0:
                tab = self.generate_tab(sp, results, results.fileid)
                gen_tab = 1

        # alert if no searches matched across all files ran
        if not gen_tab:
            self.gui.msgBox("The given path parameters returned no results.")

    def get_path_params(self):

        (pathterms, pathsfile) = self.gcommon.get_search_terms(self.gui, "path")

        if len(pathterms) == 0:
            self.gui.msgBox("No path(s) were entered. Unable to process")
            return None
       
        startDate    = self.gui.pathStartDateLineEdit.text()
        endDate      = self.gui.pathEndDateLlineEdit.text()
 
        includeVals  = self.gui.pathValuesCheckBox.isChecked() 

        return path_params(pathterms, pathsfile, includeVals, startDate, endDate)

    # called when 'search' is clicked
    def viewTree(self):

        sp = self.get_path_params()

        if not sp:
            return

        self.run_path_lookup(sp)

        # to catch anyone pulling the stale file id
        self.gui.case_obj.current_fileid = -42
   
    # puts rows into GUI table and keeps records for reporting and switching views
    def insert_results(self, tab, report_vals, searchterm, fileid):

        report = self.rm.display_reports[0]
        
        tab.tblWidget = tab.searchResTable

        tm = tmclass(report_vals)
        
        self.rm.report_tab_info(report, tm, tab, self.active_tabs, fileid, "Path", "Path Term", searchterm)

    def createReportClicked(self): 
        self.rh.createReportClicked("Path Analysis Single")
    

