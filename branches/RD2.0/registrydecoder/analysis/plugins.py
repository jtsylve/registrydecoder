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
#

import registrydecoder.analysis.base as analysisBase
import registrydecoder.common as common
import registrydecoder.regconstants as regconstants
import registrydecoder.handle_file_info as handle_file_info

from registrydecoder.errorclasses import *

class _plugin_results:
    def __init__(self, filepath, evi_file, group_name, plugin, tm, fileid, is_diff, color_idxs=[]):
        self.filepath = filepath
        self.evi_file = evi_file
        self.group_name = group_name
        self.results    = tm.report_data
        self.tm         = tm
        self.fileid     = fileid
        self.plugin     = plugin
        self.is_diff    = is_diff
        self.plugin     = plugin
        self.color_idxs = color_idxs   
 
    def __cmp__(self, other):
        return self.results == other.results

    def __eq__(self, other):
        return self.__cmp__(other)

    def hash(self):
        return str(self.results)


class pluginAnalysis(analysisBase.analysisBase):
    def __init__(self, UI):
        analysisBase.analysisBase.__init__(self, UI)
        self.defaults = ["ALL"] + regconstants.hive_types

    # remove duplicates, empty entries, etc
    def _filter_plugins(self, plugins):
        names = {}
        ret   = []

        # filter by plugin name, only return unique ones
        for p in plugins:

            if p == []:
                continue
            
            pname = p.pluginname

            if not pname in names:
                ret.append(p)    
                names[pname] = 1
                
        return ret

    # gets the actual plugins bsaed on the list of names
    def _get_plugins(self, plugin_names):
        plugins = []
        errstring = ""       
    
        for plugin_name in plugin_names:

            if plugin_name in self.defaults:
                if plugin_name == "ALL":
                    cur_plugins = self.tm.get_loaded_templates()
                else:
                    cur_plugins = self.tm.get_hive_templates(plugin_name)
                    errstring   = "No Plugins are able to process the given hive type"        

            # an actual plugin
            else:
                plugin      = self.tm.find_template(plugin_name)
                cur_plugins = [plugin]

            plugins = plugins + cur_plugins

        plugins = self._filter_plugins(plugins)

        if plugins == []:
            if len(errstring) ==  0:
                self.UI.msgBox("Unable to find chosen plugin.")
            else:
                self.UI.msgBox(errstring)

        return plugins
  
    def _run_plugins_on_fileid(self, plugins, fileid, is_diff):
        results = []

        self.UI.case_obj.current_fileid = fileid
        finfo = self.fileinfo_hash[fileid]
        (filepath, evi_file, group_name) = common.get_file_info(self.fileinfo_hash, fileid)

        for plugin in plugins:

            # if the hive the plugin supports is not the hive of the current file then skip it
            if not finfo.reg_type or not regconstants.registry_types[finfo.reg_type] in plugin.hives:
                #print "Skipping plugin %s on %s" % (plugin.name, finfo.reg_file)
                continue                    

             # run the plugin, sets report data unless required key error is thrown
            try:
                plugin.run_me()               

            except RequiredKeyError, reqkey:
                # set the error for reporting, this overwrites any data set by the plugin
                self.tm.report_error("The key %s needed by plugin %s was not found in the registy hive %s." % (reqkey, plugin.pluginname, finfo.reg_file))

            tm = self.tm.make_copy()
            results.append(_plugin_results(filepath, evi_file, group_name, plugin, tm, fileid, is_diff))

            self.tm.reset_report()
    
        return results

    # runs the given plugins against the files from the chosen tree
    def _get_plugins_output(self, plugins, fileids, is_diff):
        # htable{fileid} = list(plugin_results) for running plugins against all the chosen fileids
        results = {}

        for fileid in fileids:
            results[fileid] = self._run_plugins_on_fileid(plugins, fileid, is_diff)

        return results
    
    def _run_normal_plugins(self, plugins): 
        fileids = self.UI.get_current_fileids("plugins")

        all_results = self._get_plugins_output(plugins, fileids, 0)

        if not all_results:
            return

        found = 0
        
        for fileid in all_results:
            # results is a list of plugin_results per-plugin
            results = all_results[fileid]

            if len(results) > 0:
                found = 1 
                break

        if found == 0:
           self.UI.msgBox("No chosen plugin was able to be run against the chosen registry file(s).") 

        return all_results 

    # performs diffing for one plugin and fileid set
    def _diff_single(self, orig, new):
        (ores, ofileid) = (orig.results, orig.fileid)
        (nres, nfileid) = (new.results,  new.fileid)

        # check if error, get header from other
        orig_tm = orig.tm
        new_tm  = new.tm
        # this will be the TM sent to reporting/GUI
        use_tm  = orig.tm.make_copy()

        # try to get the real headers
        if orig_tm.error_set == 0:
            headers = orig_tm.header
        else: 
            headers = new_tm.header

        ## do actual diffing of the results
        (orig_only, new_only, orig_results) = common.diff_lists(ores, nres) 
            
        # from here to idxs = is copy/paste in seaarch.py
        data_list = orig_only + orig_results + new_only
        
        # get values to report out of search_match lists
        data_ents = [orig_only, orig_results, new_only]
        fileids   = [ofileid, ofileid, nfileid]

        # idxs to color on
        color_idxs = common.get_idxs(data_ents)

        use_tm.set_report_header(headers)
        use_tm.set_report_data(data_list)
        use_tm.timestamp = None

        results = _plugin_results("", "", "", orig.plugin, use_tm, -42, 1, color_idxs)
        
        return results

    def _run_diff_plugins(self, plugins):
        results = {}

        # one file id per widget
        fileids = self.UI.get_current_fileids("diff_plugins", 1)

        ofid = fileids[0]
        nfid = fileids[1]

        origr = self._get_plugins_output(plugins, [ofid], 1)  
        newr  = self._get_plugins_output(plugins, [nfid], 1)

        if origr == None or newr == None:
            return results

        # determine if the user chose files of different hive types
        # both trees are the same
        ofinfo = self.fileinfo_hash[ofid]
        nfinfo = self.fileinfo_hash[nfid]

        if ofinfo.reg_type != nfinfo.reg_type:
            self.UI.msgBox("The choosen files were of different registry hive types. Cannot proceed.")
            return results

        # get the list of plugin results (per-plugin) for the two chosen files
        orig_res_obj = origr[ofid]
        new_res_obj  = newr[nfid]

        if orig_res_obj == [] and new_res_obj == []:
            self.UI.msgBox("Unable to run the choosen plugin(s) against the chosen files. Cannot Proceed.")
            return results

        results[-42] = []

        # the plugins will be run in the same order on both files
        for idx in xrange(len(orig_res_obj)):
            results[-42].append(self._diff_single(orig_res_obj[idx], new_res_obj[idx]))

        return results

    def get_loaded_plugins(self):
        return self.tm.get_loaded_templates()

    def load_plugins(self):
        self.tm.load_templates(self.UI.case_obj, self.UI.plugin_dirs)

    # returns results{fileid} = [_plugin_results(), _plugin_results, ...]
    def run_plugins(self, plugin_names, perform_diff):
        self.fileinfo_hash = handle_file_info.get_hives_info(self.UI)[0]
        self.tm.load_templates(self.UI.case_obj, self.UI.plugin_dirs)

        # get the real plugin objects
        plugins = self._get_plugins(plugin_names)

        if perform_diff:
            results = self._run_diff_plugins(plugins)
        else:
            results = self._run_normal_plugins(plugins)

        return results

    def write_plugin_results(self, plugin_results, report_format="", report_filename=""):
        self.rm.start_report()

        for fileid in plugin_results:
            # _plugin_result
            for result in plugin_results[fileid]:
                tab = self.UI.generate_plugin_results_tab(result)
                self.rm.write_results(tab, result.tm, fileid, "Plugin", "Plugin Name", result.plugin.pluginname, color_idxs=result.color_idxs, report_format=report_format, report_filename=report_filename)       
    
        self.rm.end_report() 






