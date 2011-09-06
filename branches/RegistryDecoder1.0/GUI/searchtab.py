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

class search_results:

    def __init__(self, filepath, evi_file, group_name, results, fileid):

        self.filepath   = filepath
        self.evi_file   = evi_file
        self.group_name = group_name
        self.results    = results 
        self.fileid     = fileid

    # compare based on the search results only..
    def __cmp__(self, other):
        return self.results == other.results

    def __hash__(self):
        return hash(str(self.results))


class search_params:

    def __init__(self, searchterms, searchfile, partialsearch, searchKeys, searchNames, searchData, startDate, endDate):

        self.searchterms   = searchterms
        self.searchfile    = searchfile
        self.partialsearch = partialsearch
        self.searchKeys    = searchKeys
        self.searchNames   = searchNames
        self.searchData    = searchData
        self.startDate     = startDate
        self.endDate       = endDate

class searchmatch:

    def __init__(self, match, node, name="", data=""):
        
        self.node  = node
        self.name  = name
        self.data  = data
        self.match = match

    def __cmp__(self, other):
        return self.node == other.node and self.name == other.name and self.data == other.data

    def __eq__(self, other):
        return self.__cmp__(other)

    def hash(self):
        return str(self.node) + str(self.name) + str(self.data)
 
class tmclass:
       
    def __init__(self, report_vals):
 
        self.plugin_set_header = 1
        self.timestamp         = None       
        self.report_data       = report_vals 
   
class searchtab:

    def __init__(self, gui):
        self.name = "Search Tab"
        self.active_tabs = {}

        self.gui = gui

    def draw(self):
        self.fileinfo_hash = self.gcommon.fill_tree(self.gui, "searchTreeWidget")     

    def search_terms_file_browse(self):    
        filename = QFileDialog.getOpenFileName(directory="/home/x/", filter="All (*)", parent=self.gui, caption="Add Search Terms (newline seperated))")            
        
        self.gui.searchTermsLineEdit.setText(filename)

    def get_search_terms(self):    

        searchterm = unicode(self.gui.searchLineEdit.text())
    
        # the user entered a single search term
        if len(searchterm) > 0:
            searchterms = [searchterm]
            filename    = ""

        else:
            searchterms = []

            filename = unicode(self.gui.searchTermsLineEdit.text())

            try:
                fd = open(filename, "rb")
            except:
                self.gui.msgBox("Unable to open given search terms file. Cannot Proceed")
                return (searchterms, "")

            for term in fd.readlines():

                # carefully remove newlines from terms...
                if term[-1] == '\n':
                    term = term[:-1]

                if term[-1] == '\r':
                    term = term[:-1]

                searchterms.append(term)                

        return (searchterms, filename)

    def boxIsChecked(self, boxName):

        return self.gui.__getattribute__(boxName).isChecked()

    def get_search_params_boxes(self):

        return [self.boxIsChecked("searchKeysCheckBox"), self.boxIsChecked("searchNamesCheckBox"), self.boxIsChecked("searchDataCheckBox")]
       
    def get_search_params(self):

        (searchterms, searchfile)  = self.get_search_terms()

        if len(searchterms) == 0:
            self.gui.msgBox("No search term(s) were entered. Unable to process")
            return None

        partialsearch  = self.boxIsChecked("partialSearchRadioButton")

        (searchKeys, searchNames, searchData) = self.get_search_params_boxes()

        startDate    = self.gui.searchStartDateLineEdit.text()
        endDate      = self.gui.searchEndDateLlineEdit.text()
 
        return search_params(searchterms, searchfile, partialsearch, searchKeys, searchNames, searchData, startDate, endDate) 

    # get results for the given search term(s) and fileid
    def do_get_search_results(self, sp, fileid):

        results = []

        # run over all the searchterms in the same file
        for searchterm in sp.searchterms:
            results = results + self.get_search_hits(searchterm, sp.partialsearch, sp.searchKeys, sp.searchNames, sp.searchData)

        # if the user gave a search terms file
        if sp.searchfile != "":
            sp.searchterm = "from %s" % sp.searchfile
        # from the input box
        else:
            sp.searchterm = sp.searchterms[0]

        # remove results that break on the user date filtering
        if len(results) and (sp.startDate or sp.endDate):
            results = self.filter_results(results, fileid, sp.startDate, sp.endDate)

        return results
    
    # runs the given search term(s) on file id
    def run_search(self, fileid, sp):
    
        (filepath, evi_file, group_name) = self.gcommon.get_file_info(self.fileinfo_hash[fileid])

        self.gui.case_obj.current_fileid = fileid

        # results for fileid
        results = self.do_get_search_results(sp, fileid)

        return search_results(filepath, evi_file, group_name, results, fileid)

    # genereates a search result tab and fills the GUI table
    def generate_tab(self, sp, sr, fileid, color_idxs=[]):

        tab = self.gf.generate_search_view_form(self, fileid, self.gui, sr.filepath, sp.searchterm, sr.results)

        (report_vals, match_idxs) = self.get_report_vals(sr.results, fileid)

        self.insert_results(tab, report_vals, match_idxs, sp.searchterm, fileid, color_idxs)
        
        return tab

    # performs the work for a normal (non-diff) search
    # return of None means error
    # return of [] means no search matches
    def run_normal_search(self, sp):

        gen_tab = 0

        all_results = self.gcommon.run_cb_on_tree(self, self.run_search, sp, "searchTreeWidget")

        if all_results == None:
            return

        for results in all_results:

            # generate tab if they are there
            if len(results.results) > 0:
                tab = self.generate_tab(sp, results, results.fileid)
                self.setup_menu(tab)        
                gen_tab = 1

        # alert if no searches matched across all files ran
        if not gen_tab:
            self.gui.msgBox("The given search parameters returned no results.")

    def get_report_match_info(self, data_ents, fileids):

        report_vals = []
        match_idxs  = []

        for i in xrange(0, len(data_ents)):
            (r, m) = self.get_report_vals(data_ents[i], fileids[i])

            report_vals = report_vals + r
            match_idxs  = match_idxs + m

        return (report_vals, match_idxs)

    def run_diff_search(self, sp):

        # run the searches on the two trees    
        origm  = self.gcommon.run_cb_on_tree(self, self.run_search, sp, "searchTreeWidget", 1)
        newm   = self.gcommon.run_cb_on_tree(self, self.run_search, sp, "searchDiffTreeWidget", 1)

        if origm == None or newm == None:
            return

        # the lists of search matches and their fileids
        (orig_results, orig_fileid) = (origm[0].results, origm[0].fileid)
        (new_results, new_fileid)   = (newm[0].results, newm[0].fileid)

        if orig_results == [] and new_results == []:
            self.gui.msgBox("The given search parameters return no results in either chosen registry hive. Cannot proceed.")
            return

        # the resulting lsits
        (orig_only, new_only, orig_results) = self.gcommon.diff_lists(orig_results, new_results)   
     
        # build the list to be colored
        data_list = orig_only + orig_results + new_only

        # get values to report out of search_match lists
        data_ents = [orig_only, orig_results, new_only]
        fileids   = [orig_fileid, orig_fileid, new_fileid]        
 
        # idxs to color on
        idxs = self.gcommon.get_idxs(data_ents)

        # will be real values if we decide to report diff output
        sr = search_results("", "", "", data_list, -42)
        tab = self.gf.generate_search_view_form(self, -42, self.gui, sr.filepath, sp.searchterm, sr.results)
        
        tab.do_not_export = 1

        (report_vals, match_idxs) = self.get_report_match_info(data_ents, fileids)
        
        self.gcommon.hide_tab_widgets(tab)

        self.insert_results(tab, report_vals, match_idxs, sp.searchterm, -42, idxs)

    # called when 'search' is clicked
    def viewTree(self):

        sp = self.get_search_params()

        perform_diff = self.gui.performSearchDiffCheckBox.isChecked()

        if perform_diff:
            self.run_diff_search(sp)   
           
        # normal search
        else:
            self.run_normal_search(sp)

        # to catch anyone pulling the stale file id
        self.gui.case_obj.current_fileid = -42

    def setup_menu(self, tab):

        tab = tab.searchResTable
        
        tab.setContextMenuPolicy( Qt.CustomContextMenu )
        self.gui.connect(tab, SIGNAL('customContextMenuRequested(QPoint)'), self.on_context_menu)

        self.actionAdd = QAction(QString("Switch to File View"), tab) 

        self.popMenu = QMenu(tab)
        self.popMenu.addAction(self.actionAdd)

        self.gui.connect(self.actionAdd, SIGNAL("triggered()"), self.on_action_fileview)

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

    def get_current_row_node(self):
    
        curtab = self.gui.analysisTabWidget.currentWidget()
        
        self.gui.case_obj.current_fileid = curtab.fileid

        table  = curtab.searchResTable

        row    = table.currentItem()
   
        fullpath   = unicode(row.text())

        node = self.tapi.root_path_node(fullpath)[-1]
 
        return node
            
    # this is really ugly
    # sets a tree to a position based on a search hit
    def on_action_fileview(self):
        
        node  = self.get_current_row_node()

        nodes = self.tapi.node_to_root(node) + [node]

        tab   = self.gui.filetab.viewTree([self.gui.case_obj.current_fileid])         
        tree  = tab.viewTree
        model = tree.model()

        index = None
        bad   = 0
    
        for node in nodes[1:]:
            
            name = self.tapi.key_name(node)

            index = self.find_index(node, model, index)

            if not index:
                raise RDError("BAD:: no index for %d | %s" % (node.nodeid, name))
                bad = 1
                break
     
        if not bad:
            tree.setCurrentIndex(index)
        
    # find where to jump in tree       
    def find_index(self, target_node, model, start_index=None):
           
        ret = None

        if not start_index:
            start_index = QModelIndex()

        rowcount = model.rowCount(start_index)

        for i in xrange(0, rowcount):
            p = model.index(i, 0, start_index)

            ent  = p.internalPointer()
            node = self.tapi.idxtonode(ent.nid)

            if node.nodeid == target_node.nodeid:
                ret = p
                break

        return ret

    # setups right clicking on table cells
    def on_context_menu(self, point):
       
        curtab = self.gui.stackedWidget.currentWidget()

        self.popMenu.exec_( curtab.mapToGlobal(point) )
   
    # gets all the search hits into a list of searchmatch objects
    def get_search_hits(self, searchterm, partialsearch, searchKeys, searchNames, searchData):
        
        matches = []

        if searchKeys:
           
            nodes = self.tapi.node_searchfor(searchterm, partialsearch)

            for node in nodes:
                matches.append(searchmatch(0, node))  
   
        if searchNames:
            
            nodevals = self.tapi.names_for_search(searchterm, partialsearch)

            for nodeval in nodevals:
                matches.append(searchmatch(1, nodeval.node, nodeval.name))
            
        if searchData:
            
            nodevals = self.tapi.data_for_search(searchterm, partialsearch)

            for nodeval in nodevals:
                matches.append(searchmatch(2, nodeval.node, nodeval.name, nodeval.data))
            
        return matches

    def get_report_vals(self, results, fileid):

        match_idxs = []
        ret = []

        for row in xrange(len(results)):
            
            r = results[row]
            
            lastwrite = r.node.timestamps[fileid]
            lastwrite = datetime.datetime.fromtimestamp(lastwrite).strftime('%Y/%m/%d %H:%M:%S UTC')

            vals  = [lastwrite, r.node.fullpath, r.name, r.data]

            match_idxs.append(r.match+1)

            ret.append(vals)

        return (ret, match_idxs)

    # puts rows into GUI table and keeps records for reporting and switching views
    def insert_results(self, tab, report_vals, match_idxs, searchterm, fileid, color_idxs):

        report = self.rm.display_reports[0]
        
        tab.tblWidget = tab.searchResTable

        headers = ["Last Write Time", "Key", "Name", "Data"]
        report_vals = [headers] + report_vals
        
        tm = tmclass(report_vals)
        
        self.rm.report_tab_info(report, tm, tab, self.active_tabs, fileid, "Search", "Search Term", searchterm, match_idxs=match_idxs, color_idxs = color_idxs)

    # get the users date in the form of mm/dd/yyyy
    def parse_date(self, dateStr):

        ents = [int(x) for x in dateStr.split("/")]

        if len(ents) != 3:
            self.gui.msgBox("Invalid start date given.")
            ret = []
        else:
            (month, day, year) = ents
            ret = QDate(year, month, day)

        return ret

    # filter search results based on the user's choosen start and end last written dates
    def filter_results(self, results, fileid, startStr, endStr):

        # the filtered set
        ret = []

        if startStr:
            start = self.parse_date(startStr)
            if not start:
                return []
        else:
            start = ""

        if endStr:
            end = self.parse_date(endStr)
            if not end:
                return []
        else:
            end = ""

        for row in xrange(len(results)):

            r = results[row]

            # convert last written time to QDate for easy comparison to user supplied choice
            timestamp = r.node.timestamps[fileid]
            c = datetime.datetime.fromtimestamp(timestamp)
            cmpQDate = QDate(c.year, c.month, c.day)

            # this allows for narrowing by both start and end or just 1 at at ime
            if start and end:
                append = start <= cmpQDate <= end
            
            elif start:
                append = start <= cmpQDate

            elif end:
                append = end >= cmpQDate                

            else:
                print "BUG -- should not be here"

            if append:
                ret.append(r)

        return ret

    def createSearchReportClicked(self): 
        self.rh.createReportClicked("Plugin Single")
    
    def diffBoxClicked(self, isChecked):
        self.gcommon.diffBoxClicked(self, isChecked, "searchDiffTreeWidget")

