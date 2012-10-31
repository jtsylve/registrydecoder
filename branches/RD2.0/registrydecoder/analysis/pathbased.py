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

import datetime

class _path_report_info:
    def __init__(self, sp, results):
        self.sp      = sp
        self.results = results

class _path_results:
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

class _key_info:
    def __init__(self, node, vals):
        self.node = node
        self.vals = vals 

class _path_params:
    def __init__(self, pathterms, pathsfile, includeVals, startDate, endDate):
        self.pathterms   = pathterms
        self.pathsfile   = pathsfile
        self.includeVals = includeVals
        self.startDate   = startDate
        self.endDate     = endDate
        self.is_diff     = 0
        self.color_idxs  = []

class pathbasedAnalysis(analysisBase.analysisBase):
    def __init__(self, UI):
        analysisBase.analysisBase.__init__(self, UI)

    # returns None if patterm isn't a path in the current file
    def _get_path_hits(self, pathterm, includeVals):
        node = self.get_tree_node(pathterm)

        if not node:
            return None  
         
        if includeVals:
            # tuple of (name, data, raw data)
            vals = self.tapi.reg_get_values(node)
        else:
            vals = []                 

        return _key_info(node, vals)

    # get results for the given search term(s) and fileid
    def _handle_run_path_lookup(self, sp, fileid):
        results = []

        # run over all the searchterms in the same file
        for pathterm in sp.pathterms:
            hit = self._get_path_hits(pathterm, sp.includeVals)
            if hit:
                results.append(hit)

        # remove results that break on the user date filtering
        if len(results) and (sp.startDate or sp.endDate):
            results = common.filter_results(self.UI, results, fileid, sp.startDate, sp.endDate)

        return results

    def _do_run_path_lookup(self, fileid, sp):
        (filepath, evi_file, group_name) = common.get_file_info(self.fileinfo_hash, fileid)

        self.UI.case_obj.current_fileid = fileid

        # results for fileid
        results = self._handle_run_path_lookup(sp, fileid)

        return _path_results(filepath, evi_file, group_name, results, fileid)

    def _run_path_on_fileids(self, cb, sp, fileids):
        results = []

        for fileid in fileids:
            results = results + [cb(fileid, sp)]

        return results

    # performs the work for a path lookup
    # return of None means error
    # return of [] means no search matches
    def _run_path_lookup(self, sp):
        fileids = self.UI.get_current_fileids("path")    
    
        all_results = self._run_path_on_fileids(self._do_run_path_lookup, sp, fileids)

        if all_results == None:
            return

        ret_results = []
        for results in all_results:
            if len(results.results) > 0:
                ret_results.append(results)

        if len(ret_results) == 0:
            self.UI.msgBox("The given path parameters returned no results.")

        return ret_results

    # results is a list of key_info
    def _get_report_vals(self, includeVals, results, fileid, _is_diff):
        ret = []

        for row in xrange(len(results)):
            r = results[row]

            lastwrite = r.node.timestamps[fileid]
            lastwrite = datetime.datetime.fromtimestamp(lastwrite).strftime('%Y/%m/%d %H:%M:%S')

            # add the path and its last write time
            ret.append([self.tapi.full_path_node_to_root(r.node), lastwrite])

            if includeVals == 1:
                # add any values
                for val_ent in r.vals:
                    (name, val, rval) = val_ent
                    ret.append(["", name, val])

        return (ret, [])   
    
    def set_analysis_params(self, pathterm, pathsfile, includeVals, startDate, endDate):
        pathterms = common.valid_file_date_params(self.UI, pathterm, pathsfile, startDate, endDate)
        
        if pathterms:
            ret = _path_params(pathterms, pathsfile, includeVals, startDate, endDate)
        else:
            ret = None
    
        return ret
    
    # returns _path_report_info of (sp, [_path_rseults])
    def run_path_analysis(self, sp):
        self.fileinfo_hash = handle_file_info.get_hives_info(self.UI)[0]
        
        results = self._run_path_lookup(sp) 

        return _path_report_info(sp, results) 

    def write_path_results(self, path_results, report_format="", report_filename=""):
        sp = path_results.sp
        
        self.rm.start_report()

        for results in path_results.results:
            (report_vals, match_idxs) = self._get_report_vals(sp.includeVals, results.results, results.fileid, results.is_diff)
        
            self.tm.set_report_header([])
            self.tm.set_report_data(report_vals)
        
            tab = self.UI.generate_path_results_tab(sp, results, results.fileid)

            self.rm.write_results(tab, self.tm, results.fileid, "Path Analysis", "Path", sp.pathterms, match_idxs=match_idxs, color_idxs=results.color_idxs, report_format=report_format, report_filename=report_filename)

        self.rm.end_report()      

    def _get_path_node(self, path):        
        nodes = self.tapi.root_path_node(path)     

        if nodes:
            node = nodes[-1]
        else:
            return None 

        return node

    def get_tree_node(self, userpath=""):
        ret = None

        if userpath:
            path = userpath
            ok   = True
        else:
            (path, ok) = self.UI.get_registry_path_from_user()

        if ok and (userpath or not path.isEmpty()):
            # try to help out the user 
            
            # if they didn't give leading \, add it
            if path[0] != "\\":
                path = "\\" + path

            # if they gave a trailing \, strip it
            if path[-1] == "\\":
                path = path[:-1]

            fullpath = unicode(self.tapi.get_path(path))

            ret = self._get_path_node(fullpath)

        return ret


