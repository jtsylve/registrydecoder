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

# just here to tag members on
class o:
    pass

import handle_file_info 
import common

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from xlwt import Workbook

class _header_info:
    def __init__(self, action, context, term, extras, fileid):        
        self.action    = action
        self.context   = context
        self.term      = term
        self.extras    = extras
        self.fileid    = fileid

class _report_params:
    def __init__(self, fileid, action, context, term):
        self.fileid  = fileid
        self.action  = action
        self.context = context
        self.term    = term

class _info_class:    
    def __init__(self, tm, hinfo, cinfo_list, header_list, rdata, rows_max, cols_max, match_idxs, color_idxs):
        self.header_info = hinfo
        self.case_info_list  = cinfo_list
        self.header_list = header_list
        self.rdata       = rdata
        self.rows_max    = rows_max
        self.cols_max    = cols_max
        self.color_idxs  = color_idxs
        self.tm          = tm
        self.match_idxs  = match_idxs

class report_manager:
    def __init__(self, UI):
        self.reports = []
        self.report_hash = {}
        self.evidence_hash = {}

        self.directory = os.path.join("registrydecoder", "reporting", "report_formats")
        sys.path.append(self.directory)
       
        self.UI = UI

        self.load_report_formats()
      
        self.start_report()
 
    def start_report(self):
        self.shown_cinfo = False

    def end_report(self):
        self.start_report()

    def load_report_formats(self):
        # load the reports if not already done
        # to be efficient, we only load them once
        if self.reports == []:
            self.load_reports()

            for r in self.reports:
                self.report_hash[r.name] = r

    def get_loaded_reports(self):
        return self.reports

    def get_loaded_report_types(self):
        return [r.name for r in self.reports] 
       
    def load_reports(self):
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
                        self.reports.append(mod)
    
    # this is to get data to report about the file/action besides the standard items
    # currently only used by the plugintab if/when a global timestamp is set
    def _get_extra_header_info(self, tm):
        # This becomes a hashtable of {"header name":"header value"} for each item set
        extras = {}

        if tm.timestamp:            
            extras["Plugin Timestamp"] = tm.timestamp

        return extras

    def _get_info_vars(self, tab, tm, rps, match_idxs, color_idxs):
        
        # this refreshes the report data with whats currently in the table
        # allows for sorting/deleting/etc
        if tab and hasattr(self.UI, "get_report_info_from_tab"):
            temp_tm = self.UI.get_report_info_from_tab(tab)
            if temp_tm:
                tm = temp_tm

        (header_list, rdata, rows_max, cols_max) = self._get_report_data(tm)
        
        extras      = self._get_extra_header_info(tm)
        cinfo_list = self._get_case_info_list(rps.fileid)
        hinfo      = _header_info(rps.action, rps.context, rps.term, extras, rps.fileid)

        info_class = _info_class(tm, hinfo, cinfo_list, header_list, rdata, rows_max, cols_max, match_idxs, color_idxs)

        return info_class

    def _export_report(self, report_obj, report_filename, info_class, tab_info, cinfo):
        if not report_filename or len(report_filename) == 0:
            self.UI.msgBox("Create Report button clicked but no report filename was given. Cannot Proceed.")
            return
        
        repext   = "." + report_obj.extension
              
        # if the user didn't supply an extension, then append it (given from report module)
        if not report_filename.endswith(repext):
            report_filename = report_filename + repext

        self._report_single(report_obj, report_filename, info_class, tab_info, cinfo)

    def _get_report_info(self, report_format, tab, tm, report_params, append, match_idxs=[], color_idxs=[]):
        # get file based report or the screen/cmdline display report
        try:
            report_obj = self.report_hash[report_format]
        except:
            report_obj = self.UI.report_obj.get_instance()

        info_class = self._get_info_vars(tab, tm, report_params, match_idxs, color_idxs)
        
        return (info_class, report_obj)

    def _write_to_ui(self, tab, info_class, report_obj, report_filename):
        tm = info_class.tm 

        if tab:
            tab.info_class = info_class
            self.UI.fill_info(tab) 
            tbl = tab.tblWidget
        else:
            tbl = None
             
        report_obj.report_data(tbl, tm.header, tm.report_data, info_class)

    def _write_report(self, tab, info_class, report_obj, report_filename, append=0):
        # this write to the UI-defined report
        if self.shown_cinfo == False:
            cinfo = True
            self.shown_cinfo = True
        else:
            cinfo = False

        self._export_report(report_obj, report_filename, info_class, tab, cinfo)
         
        if append == 0:
            report_obj.close_report()

    # called per file results (e.g. per-tab)
    # info_class is set when the GUI writes out a report
    def write_results(self, tab, tm, fileid, action, context, term, append=0, match_idxs=[], color_idxs=[], report_format="", report_filename=""):
        report_params = _report_params(fileid, action, context, term)    
        (info_class, report_obj) = self._get_report_info(report_format, tab, tm, report_params, append, match_idxs, color_idxs)

        if report_format == "" or report_format == None:
            self._write_to_ui(tab, info_class, report_obj, report_filename)
        else:
            self._write_report(tab, info_class, report_obj, report_filename)
        
    def _get_case_info_list(self, fileid):
        db = self.UI.case_obj.caseinfodb

        db.cursor.execute("select casename,casenumber,investigatorname,comments from caseinformation")
        
        (casename, casenum, iname, comments) = db.cursor.fetchone()

        return [("Case Name", casename), ("Case Number", casenum), ("Investigator Name", iname), ("Comments", comments), ("Report Time", time.strftime("%Y/%m/%d %H:%M:%S"))]

    def _get_hinfo_list(self, hinfo):
        case_obj = self.UI.case_obj

        # header list
        hl = ["Evidence File", "Evidence Alias", "Registry File Group", "Registry File", "Analysis Type", hinfo.context]

        # get the hash table of fileid mappings
        fhash = handle_file_info.get_hives_info(self.UI)[0]

        (evi_file, group_info, alias, reg_file) = common.get_file_info(fhash, hinfo.fileid, 1)

        if alias == evi_file:
            alias = ""

        ret = [(hl[0], evi_file),
               (hl[1], alias),
               (hl[2], group_info),
               (hl[3], reg_file),
               (hl[4], hinfo.action),
               (hl[5], hinfo.term)]

        for key in hinfo.extras:
            val = hinfo.extras[key]

            ret.append((key,val))

        return ret

    # perform all report functions at once
    # this for file-based report
    def _report_single(self, report, report_filename, info_class, tab, cinfo):
        hinfo      = info_class.header_info
        hinfo_list = self._get_hinfo_list(hinfo)
        cinfo_list = info_class.case_info_list

        (header_list, rdata, rows_max, cols_max) = (info_class.header_list, info_class.rdata, info_class.rows_max, info_class.cols_max)
        

        # start output, set variables
        report.set_file(report_filename)
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
    def _get_report_data(self, tm):
        
        # get the max number of columns and rows to help report formats
        rdata = tm.report_data
        header_list = tm.header

        rows = []
        cols = []

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

             
