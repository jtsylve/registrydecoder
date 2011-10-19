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
import os, sys, time, codecs

import GUI.guicommon as gcommon

# just here to tag members on
class o:
    pass

class header_info:

    def __init__(self, analysis_type, col_info, term, extras, fileid):
        
        self.analysis_type = analysis_type
        self.col_info      = col_info
        self.term          = term
        self.extras        = extras
        self.fileid        = fileid

def get_hinfo_list(hinfo, gui):

    case_obj = gui.case_obj

    # header list
    hl = ["Evidence File", "Evidence Alias", "Registry File Group", "Registry File", "Analysis Type", hinfo.col_info]

    fhash = gcommon.fill_tree(gui, "", 0)

    (evi_file, group_info, alias, reg_file) = gcommon.get_file_info(fhash, hinfo.fileid, 1)

    if alias == evi_file:
        alias = ""

    ret = [(hl[0], evi_file),
           (hl[1], alias),
           (hl[2], group_info),
           (hl[3], reg_file),
           (hl[4], hinfo.analysis_type),
           (hl[5], hinfo.term)]

    for key in hinfo.extras:
        val = hinfo.extras[key]

        ret.append((key,val))

    return ret

def get_report_info(tab):

    class b:
        pass

    tm = b()

    data    = []
    tbl  = tab.tblWidget

    tm.report_data       = data
    tm.plugin_set_header = tab.plugin_set

    rcount = tbl.rowCount()
    ccount = tbl.columnCount()

    # grab the headeres if they need to be set
    headers = []

    # keeps track of where we are in the data list
    didx = 0

    # limit to users selections
    selected_rows = []    

    selected = tbl.selectedIndexes()
    
    selectonly = len(selected) > 0

    for index in selected:
    
        selected_rows.append(index.row())

    if tm.plugin_set_header:

        for c in xrange(0, ccount):

            item = tbl.horizontalHeaderItem(c) 

            if item:
                headers.append(unicode(item.text()))

        data.append(headers)

        didx = 1

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
    return get_report_data(tm)

# perform all report functions at once
def report_single(report, filename, tab, cinfo=True):

    hinfo      = tab.header_info
    cinfo_list = tab.case_info_list

    (header_list, rdata, rows_max, cols_max) = get_report_info(tab)
    
    hinfo_list = get_hinfo_list(hinfo, report.gui)

    # start output, set variables
    report.set_file(filename)
    report.start_output()
    report.set_table_size(rows_max, cols_max)
  
    if not hasattr(report, "no_case_info"):

        # write info about case
        # only write if set so that it only shows once during bulk export
        if cinfo:
            report.start_table()
            report.write_data_list(cinfo_list, 0)
            report.end_table()
     
        # write table with information about file and action performed
        
        report.start_table()
        report.write_data_list(hinfo_list, 0)
        report.end_table()

    # write the table with plugin/search output
    report.start_table()

    # headers
    report.start_column()
    report.write_number_column()
    report.write_table_headers(header_list)
    report.end_column()
    
    # data
    report.write_data_list(rdata, 1)
    report.end_table()

    # end output
    report.end_output()

# calculate row/col info so each plugin doesn't have to
def get_report_data(tm):
    
    # get the max number of columns and rows to help report formats
    rdata = tm.report_data

    rows = []
    cols = []

    if tm.plugin_set_header:
        header_list = rdata[0]
        idx = 1
    else:
        header_list = []
        idx = 0

    # get the output values
    if len(rdata) > 0:
        rdata = rdata[idx:]

    #print "header_list: %s" % str(header_list)

    rows.append(len(rdata))

    for outer in rdata:
        cols.append(len(outer))

    if rows == []:
        rows_max = 1
    else:
        rows_max = max(rows)

    # ensure headers are drawn
    if cols == []:
        cols_max = len(header_list)
    else:
        cols_max = max(cols)    

    if header_list == []:
        header_list = [""] * cols_max

    return (header_list, rdata, rows_max, cols_max)

class report_manager:

    def __init__(self, gui):
        self.reports = []
        self.report_hash = {}
        self.evidence_hash = {}
        self.display_reports = []
        
        self.get_report_data = get_report_data

        self.directory = os.path.join("reporting", "report_formats")
        sys.path.append(self.directory)
       
        self.gui = gui

        self.load_report_formats()
       
    def load_report_formats(self):
    
        # load the reports if not already done
        # to be efficient, we only load them once
        if self.display_reports == []:
            self.load_reports(0)
            self.display_reports = self.get_loaded_reports()
            
            self.load_reports(1)
            self.file_reports = self.get_loaded_reports()

            # fill hash table
            for r in self.display_reports:
                self.report_hash[r.name] = r

            for r in self.file_reports:
                self.report_hash[r.name] = r

    def get_loaded_reports(self):
        return self.reports

    # loads reports that match file_based, based on load_templates
    def load_reports(self, file_based):

        required_attrs = ["get_instance"]
        
        self.reports = []
        
        if '_MEIPASS2' in os.environ:
            self.directory = os.path.join(os.environ['_MEIPASS2'], "reportingg")
            sys.path.append(self.directory)
        
        for root, dirs, files in os.walk(self.directory):
            for fd in files:
                if fd.endswith(".py"):
                    modname = fd.rsplit(".")[0]
                
                    mod = __import__(modname)       
 
                    valid = 1
                    for attr in required_attrs:
                        if not hasattr(mod, attr):
                            valid = 0
                            break
                                        
                    if valid:
                        mod = mod.get_instance()
                        if hasattr(mod, "fileoutput") and mod.fileoutput == file_based:
                            setattr(mod, "report_single", report_single) 
                            setattr(mod, "gui",      self.gui)
                            self.reports.append(mod)
        
    # this is to get data to report about the file/action besides the standard items
    # currently only used by the plugintab if/when a global timestamp is set
    def get_extra_header_info(self, tm):

        # This becomes a hashtable of {"header name":"header value"} for each item set
        extras = {}

        if tm.timestamp:            
            extras["Plugin Timestamp"] = tm.timestamp

        return extras

    def report_tab_info(self, report_instance, tm, tab, active_tabs, fileid, action, context, term, match_idxs=[], color_idxs=[]):

        extras = self.get_extra_header_info(tm)

        hinfo = header_info(action, context, term, extras, fileid)
        cinfo_list = self.get_case_info_list(fileid)

        # set all the info about the specific tab...
        active_tabs[tab] = o()
        active_tabs[tab].header_info    = hinfo
        active_tabs[tab].case_info_list = cinfo_list
        active_tabs[tab].match_idxs     = match_idxs
        active_tabs[tab].plugin_set     = tm.plugin_set_header
        active_tabs[tab].tblWidget      = tab.tblWidget

        (header_list, rdata, rows_max, cols_max) = self.get_report_data(tm)
        
        # write to newly created tab in GUI
        report_instance.report_data(tab.tblWidget, header_list, rdata, match_idxs, rows_max, cols_max, color_idxs)

    def get_case_info_list(self, fileid):
        
        db = self.gui.case_obj.caseinfodb

        db.cursor.execute("select casename,casenumber,investigatorname,comments from caseinformation")
        
        (casename, casenum, iname, comments) = db.cursor.fetchone()

        return [("Case Name", casename), ("Case Number", casenum), ("Investigator Name", iname), ("Comments", comments), ("Report Time", time.strftime("%Y/%m/%d %H:%M:%S"))]




         
