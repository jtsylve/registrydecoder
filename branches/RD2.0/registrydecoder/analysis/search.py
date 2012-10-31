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

import registrydecoder.analysis.base as analysisBase
import registrydecoder.common as common
import registrydecoder.handle_file_info as handle_file_info

class _search_report_info:
    def __init__(self, sp, results):
        self.sp      = sp
        self.results = results

class _search_results:
    def __init__(self, filepath, evi_file, group_name, results, fileid, color_idxs=[], is_diff=0):
        self.filepath   = filepath
        self.evi_file   = evi_file
        self.group_name = group_name
        self.results    = results 
        self.fileid     = fileid
        self.color_idxs = color_idxs
        self.is_diff    = is_diff

    # compare based on the search results only..
    def __cmp__(self, other):
        return self.results == other.results

    def __hash__(self):
        return hash(str(self.results))

class _search_params:
    def __init__(self, searchterms, searchfile, partialsearch, searchKeys, searchNames, searchData, startDate, endDate):
        self.searchterms   = searchterms
        self.searchfile    = searchfile
        self.partialsearch = partialsearch
        self.searchKeys    = searchKeys
        self.searchNames   = searchNames
        self.searchData    = searchData
        self.startDate     = startDate
        self.endDate       = endDate

class _search_match:
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
 
class searchAnalysis(analysisBase.analysisBase):
    def __init__(self, UI):
        analysisBase.analysisBase.__init__(self, UI)
    
    def set_search_params(self, searchterm, searchfile, partialsearch, searchKeys, searchNames, searchData, startDate, endDate):
        searchterms = common.valid_file_date_params(self.UI, searchterm, searchfile, startDate, endDate)
        
        if searchterms:
            ret = _search_params(searchterms, searchfile, partialsearch, searchKeys, searchNames, searchData, startDate, endDate)
        else:
            ret = None

        return ret

    def perform_search(self, sp, perform_diff):
        self.fileinfo_hash = handle_file_info.get_hives_info(self.UI)[0]

        if perform_diff:
            results = self._run_diff_search(sp)   
        else:
            results = self._run_normal_search(sp)

        return _search_report_info(sp, results)

    # search_results from perform_search, instance of _search_report_info
    def write_search_results(self, search_results, report_format="", report_filename=""):  
        sp = search_results.sp
        
        self.rm.start_report()

        for results in search_results.results:
            (report_vals, match_idxs) = self._get_report_vals(results.results, results.fileid, results.is_diff)
        
            if results.is_diff:
                self.tm.set_report_header(["Key", "Name", "Data"])
            else:
                self.tm.set_report_header(["Last Write Time", "Key", "Name", "Data"])

            self.tm.set_report_data(report_vals)
        
            tab = self.UI.generate_search_results_tab(sp, results, results.fileid,  results.color_idxs)

            self.rm.write_results(tab, self.tm, results.fileid, "Search", "Search Term", sp.searchterm, match_idxs=match_idxs, color_idxs=results.color_idxs, report_format=report_format, report_filename=report_filename)

        self.rm.end_report()

    # get results for the given search term(s) and fileid
    def _do_get_search_results(self, sp, fileid):
        results = []

        # run over all the searchterms in the same file
        for searchterm in sp.searchterms:
            results = results + self._get_search_hits(searchterm, sp.partialsearch, sp.searchKeys, sp.searchNames, sp.searchData)

        # if the user gave a search terms file
        if sp.searchfile != "":
            sp.searchterm = "from %s" % sp.searchfile
        # from the input box
        else:
            sp.searchterm = sp.searchterms[0]
   
        # remove results that break on the user date filtering
        if len(results) and (sp.startDate or sp.endDate):
            results = common.filter_results(self.UI, results, fileid, sp.startDate, sp.endDate)
        
        return results
    
    # runs the given search term(s) on file id
    def _run_search(self, fileid, sp):
        (filepath, evi_file, group_name) = common.get_file_info(self.fileinfo_hash, fileid)

        self.UI.case_obj.current_fileid = fileid

        # results for fileid
        results = self._do_get_search_results(sp, fileid)

        return _search_results(filepath, evi_file, group_name, results, fileid)

    def _run_diff_search(self, sp):
        # this will return a list of two fileids
        fileids = self.UI.get_current_fileids("diff_search")

        origm = self._run_search_on_fileids(self._run_search, sp, [fileids[0]])
        newm = self._run_search_on_fileids(self._run_search, sp, [fileids[1]])

        if origm == None or newm == None:
            return []

        # the lists of search matches and their fileids
        (orig_results, orig_fileid) = (origm[0].results, origm[0].fileid)
        (new_results, new_fileid)   = (newm[0].results, newm[0].fileid)

        if orig_results == [] and new_results == []:
            self.UI.msgBox("The given search parameters return no results in either chosen registry hive. Cannot proceed.")
            return []

        # the resulting lsits
        (orig_only, new_only, orig_results) = common.diff_lists(orig_results, new_results)   
     
        # build the list to be colored
        data_list = orig_only + orig_results + new_only

        # get values to report out of search_match lists
        data_ents = [orig_only, orig_results, new_only]
        fileids   = [orig_fileid, orig_fileid, new_fileid]        

        color_idxs = common.get_idxs(data_ents)

        # will be real values if we decide to report diff output generically
        results  = [_search_results("", "", "", data_list, -59, color_idxs=color_idxs, is_diff=1)]

        return results

    def _run_search_on_fileids(self, cb, sp, fileids):
        results = []

        for fileid in fileids:
            results = results + [cb(fileid, sp)]

        return results

    def _get_report_vals(self, results, fileid, is_diff):
        match_idxs = []
        ret = []

        for row in xrange(len(results)):
            r = results[row]

            if is_diff == 0:
                lastwrite = r.node.timestamps[fileid]
                lastwrite = common.get_time_for_lastwrite(lastwrite)

                vals  = [lastwrite, r.node.fullpath, r.name, r.data]
                match_idxs.append(r.match+1)
            else:
                vals  = [r.node.fullpath, r.name, r.data]
                match_idxs.append(r.match)

            ret.append(vals)

        return (ret, match_idxs)

    # performs the work for a normal (non-diff) search
    # return of None means error
    # return of [] means no search matches
    def _run_normal_search(self, sp):        
        ret_results = []

        fileids = self.UI.get_current_fileids("search")
        all_results = self._run_search_on_fileids(self._run_search, sp, fileids) 

        for results in all_results:

            if len(results.results) > 0:
                ret_results.append(results)

        # alert if no searches matched across all files ran
        if len(ret_results) == 0:
            self.UI.msgBox("The given search parameters returned no results.")

        return ret_results

    # gets all the search hits into a list of searchmatch objects
    def _get_search_hits(self, searchterm, partialsearch, searchKeys, searchNames, searchData):
        matches = []
        
        if searchKeys:
            nodes = self.tapi.node_searchfor(searchterm, partialsearch)
            for node in nodes:
                matches.append(_search_match(0, node))  
   
        if searchNames:
            nodevals = self.tapi.names_for_search(searchterm, partialsearch)
            for nodeval in nodevals:
                
                matches.append(_search_match(1, nodeval.node, nodeval.name, nodeval.data))
            
        if searchData:
            nodevals = self.tapi.data_for_search(searchterm, partialsearch)
            for nodeval in nodevals:
                matches.append(_search_match(2, nodeval.node, nodeval.name, nodeval.data))
            
        return matches

    
