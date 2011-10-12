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
# controls the plugin case analysis tab

import sys, copy

from errorclasses import *

from PyQt4.QtCore    import *
from PyQt4.QtGui     import *
from PyQt4.QtNetwork import *

from guicontroller import *

import common

rolenum = 32

class tmclass:
       
    def __init__(self, report_vals, pset):
 
        self.plugin_set_header = pset
        self.timestamp         = None       
        self.report_data       = report_vals 
 
class plugin_results:

    def __init__(self, filepath, evi_file, group_name, plugin, tm, fileid):

        self.filepath = filepath
        self.evi_file = evi_file
        self.group_name = group_name
        self.results    = tm.report_data
        self.tm         = tm
        self.fileid     = fileid
        self.plugin     = plugin
    
    def __cmp__(self, other):
        return self.results == other.results

    def __eq__(self, other):
        return self.__cmp__(other)

    def hash(self):
        return str(self.results)

class plugintab:

    def __init__(self, gui):

        self.name = "Plugin Tab"
        self.gui = gui
        self.active_tabs = {}
        
        self.defaults = ["ALL"] + common.hive_types    
        self.current_hive = ""

    # remove duplicates, empty entries, etc
    def filter_plugins(self, plugins):

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

    # get plugins to run after button is clicked
    def get_plugins(self):

        errstring = ""       

        # the plugins to be run
        plugins = []

        selected_plugins = self.gui.pluginListWidget.selectedItems()

        if len(selected_plugins) == 0:
            self.gui.msgBox("No plugin was seletected to be run.")
            return selected_plugins

        # all the user choosen plugins
        for item_w in selected_plugins:

            # the plugins for this selection
            cur_plugins = []

            plugin_name = unicode(item_w.text())

            # software/system/sam/etc
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

        if plugins:
            plugins = self.filter_plugins(plugins)

        if plugins == []:
            if len(errstring) ==  0:
                raise RDError("Unable to find chosen plugin.")
            else:
                self.gui.msgBox(errstring)

        return plugins
      
    # clicked from indiviual plugin output forms 
    def createReportClicked(self):
        self.rh.createReportClicked("Plugin Single")

    def run_plugins(self, fileid, plugins):

        results = []

        self.gui.case_obj.current_fileid = fileid

        (filepath, evi_file, group_name) = self.gcommon.get_file_info(self.fileinfo_hash, fileid)

        finfo = self.fileinfo_hash[fileid]

        for plugin in plugins:

            # if the hive the plugin supports is not the hive of the current file then skip it
            if not finfo.reg_type or not registry_types[finfo.reg_type] in plugin.hives:
                #print "Skipping plugin %s on %s" % (plugin.name, finfo.reg_file)
                continue                    

             # run the plugin, sets report data unless required key error is thrown
            try:
                plugin.run_me()               

            except RequiredKeyError, reqkey:
                # set the error for reporting, this overwrites any data set by the plugin
                self.tm.report_data = [["Error"], ["The key %s needed by plugin %s was not found in the registy hive %s." % (reqkey, plugin.pluginname, finfo.reg_file)]]
                self.tm.plugin_set_header = 1 

            # b/c the report gets reset after each run
            tm = self.copy_tm(self.tm)

            results.append(plugin_results(filepath, evi_file, group_name, plugin, tm, fileid))
            
            self.tm.reset_report() 

        return results

    # runs the given plugins against the files from the chosen tree
    def get_plugins_output(self, tree_name, plugins, max_files=-1):

        # htable{fileid} = list(plugin_results) for running plugins against all the chosen fileids
        results = {}

        fileids = self.gcommon.get_file_ids(self, tree_name, max_files)  

        if fileids == None:
            return
       
        for fileid in fileids:

            results[fileid] = self.run_plugins(fileid, plugins)

        return results
    
    def get_label_text(self, plugin, filepath):

        return "Results for running %s against %s" % (plugin, filepath)

    def generate_tab(self, r):   
 
        # generate form for output
        tab = self.gf.plugin_export_form(self, r.fileid, r.plugin.pluginname, self.get_label_text(r.plugin.pluginname, r.filepath)) 
        
        self.rm.report_tab_info(self.rm.display_reports[0], r.tm, tab, self.active_tabs, r.fileid, "Plugin", "Plugin Name", r.plugin.pluginname)

        # the results are now in the GUI...

        tab.tblWidget.resizeColumnsToContents()
        
    def run_normal_plugins(self, plugins): 

        all_results = self.get_plugins_output("pluginFilestreeWidget", plugins)

        if not all_results:
            return

        # tracks if a plugin was found
        tab_gen     = 0
        
        for fileid in all_results:
            # results is a list of plugin_results per-plugin
            results = all_results[fileid]

            for result in results:

                self.generate_tab(result)
                tab_gen = 1 

        if tab_gen == 0:
           self.gui.msgBox("No chosen plugin was able to be run against the chosen registry file(s).") 

    def run_diff_plugins(self, plugins):

        origr = self.get_plugins_output("pluginFilestreeWidget", plugins, 1)  
        newr  = self.get_plugins_output("pluginDiffTreeWidget",  plugins, 1)

        if origr == None or newr == None:
            return

        # the file id of the first file chosen
        ofid = origr.keys()[0]
        nfid = newr.keys()[0]
    
        # determine if the user chose files of different hive types
        # both trees are the same
        ofinfo = self.fileinfo_hash[ofid]
        nfinfo = self.fileinfo_hash[nfid]

        if ofinfo.reg_type != nfinfo.reg_type:
            self.gui.msgBox("The choosen files were of different registry hive types. Cannot proceed.")
            return

        # get the list of plugin results (per-plugin) for the two chosen files
        orig_res_obj = origr[ofid]
        new_res_obj  = newr[nfid]

        if orig_res_obj == [] and new_res_obj == []:
            self.gui.msgBox("Unable to run the choosen plugin(s) against the chosen files. Cannot Proceed.")
            return

        # the plugins will be run in the same order on both files
        for idx in xrange(len(orig_res_obj)):

            self.diff_single(orig_res_obj[idx], new_res_obj[idx])

    # performs diffing for one plugin and fileid set
    def diff_single(self, orig, new):

        (ores, ofileid) = (orig.results, orig.fileid)
        (nres, nfileid) = (new.results,  new.fileid)

        # plugin doesnt set header but one of them errored
        if new.tm.plugin_set_header == 1 and orig.tm.plugin_set_header == 0:
            
            # this will grab the error column
            
            appheader = [nres[0]]
            nres      = nres[1:]
                
            sendores = ores
            
            orig.tm.plugin_set_header = 1
        
        elif new.tm.plugin_set_header == 0 and orig.tm.plugin_set_header == 1:
        
             appheader = [ores[0]]
             sendores      = ores[1:]   
             
        elif new.tm.plugin_set_header == 1:
        
            # strip the header from the second results if set
            if len(nres) > 0:
                nheader = nres[0]
                nres = nres[1:]
    
            if len(ores) > 0:
                sendores = ores[1:]

                # if one plugin errors (meaning key not there) then use header from successful one
                if len(ores) > 0 and len(ores[0]) > 0 and ores[0][0] == 'Error':
                    ores[0] = nheader

                appheader = [ores[0]]
            else:
                sendores = ores
                appheader = []
        else:
            sendores = ores
            appheader = []
        
        #print "nres after: %s" % str(ores)                
        (orig_only, new_only, orig_results) = self.gcommon.diff_lists(sendores, nres) 
            
        #print "%d\n%d\n%d\n" % (len(orig_only), len(new_only), len(orig_results))
        #print "%s\n\n\n%s\n\n\n%s" % (str(orig_only), str(new_only), str(orig_results))
        
        data_list = appheader + orig_only + orig_results + new_only
        
        # get values to report out of search_match lists
        data_ents = [orig_only, orig_results, new_only]
        fileids   = [ofileid, ofileid, nfileid]

        # idxs to color on
        idxs = self.gcommon.get_idxs(data_ents)

        #print "idxs: %s" % str(idxs)
        
        #print "idxs: %s" % str(idxs)
        
        # will be real values if we decide to report diff output
        tab = self.gf.plugin_export_form(self, -42, orig.plugin.pluginname, self.get_label_text(r.plugin.pluginname, r.filepath))
        
        tab.do_not_export = 1

        self.gcommon.hide_tab_widgets(tab)

        tm = tmclass(data_list, orig.tm.plugin_set_header)

        # for now orig.tm works b/c we just need to know if the plugin set a header and/or a timestamp
        self.rm.report_tab_info(self.rm.display_reports[0], tm, tab, self.active_tabs, -42, "Plugin", "Plugin Name", "Plugin Diff", color_idxs=idxs)

    # called when run plugin button is clicked 
    def run_plugin(self):

        # a list of template instances to run
        plugins = self.get_plugins()

        if plugins == []:
            return

        perform_diff = self.gui.pluginDiffCheckBox.isChecked()

        if perform_diff:
            self.run_diff_plugins(plugins)

        else:
           self.run_normal_plugins(plugins)

        self.gui.case_obj.current_fileid = -42

    # add an item to a combo box
    def addItem(self, box, val, userdata=None):

        self.gui.__getattribute__(box).addItem(QString(val), QVariant(userdata))

    # currently only used for plugins list
    def addListItem(self, list_widget_name, val, userdata=None):

        list_w = self.gui.__getattribute__(list_widget_name)

        # get the list item
        item = QListWidgetItem(QString(val))

        # associate the value with it
        # item.setData(rolenum, QVariant(userdata))
        
        if userdata:
            item.setToolTip(QString(userdata.description))

        # add into the list
        list_w.addItem(item)
        
    def fill_hive_combobox(self):
     
        self.addItem("hiveComboBox","ALL")

        for reg_type in registry_types.values():
           
            self.addItem("hiveComboBox", reg_type)

    # updates the current hive
    # redraws to reflect
    def update_hive(self, index):

        hive_text = unicode(self.gui.hiveComboBox.currentText())

        if hive_text:
            self.current_hive = hive_text            

        else:
            self.current_hive = ""
    
        self.fill_plugin_listwidget()

    def fill_plugin_listwidget(self):
        
        widgetname = "pluginListWidget"

        # load the templates/plugins
        self.tm.load_templates(self.gui.case_obj, self.gui.plugin_dirs)

        self.gui.pluginListWidget.clear()

        # set the registry types
        if self.current_hive in ["", "ALL"]:
            for i in self.defaults:
                self.addListItem(widgetname, i)
        else:
            self.addListItem(widgetname, self.current_hive)

        # set the plugins for the hive type or list all
        templates = self.tm.get_loaded_templates()

        ts = {}

        for t in templates:
            if self.current_hive in ["", "ALL"] or self.current_hive in t.hives:
                ts[t.pluginname] = t 

        # plugins in abc order
        for tname in sorted(ts.keys()):
            t = ts[tname]

            self.addListItem(widgetname, tname, t)

    def fill_file_tree(self):
        self.fileinfo_hash = self.gcommon.fill_tree(self.gui, "pluginFilestreeWidget")
        
    def draw(self):
        # don't change the order...
        self.fill_hive_combobox()
        self.fill_plugin_listwidget()
        self.fill_file_tree()

    def copy_tm(self, tm):
        
        class t:
            pass

        # copy out the attributes, copy.deepcopy is retarded
        tm2 = t()
        for attr in dir(tm):
            if not attr.startswith("__"):
                setattr(tm2, attr, getattr(tm, attr))
    
        return tm2 

    def diffBoxClicked(self, isChecked):
        self.gcommon.diffBoxClicked(self, isChecked, "pluginDiffTreeWidget")




