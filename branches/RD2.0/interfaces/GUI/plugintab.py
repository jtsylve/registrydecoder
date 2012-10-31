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

from PyQt4.QtCore    import *
from PyQt4.QtGui     import *
from PyQt4.QtNetwork import *

rolenum = 32

class plugintab:
    def __init__(self, gui):
        self.name = "Plugin Tab"
        self.gui = gui
        self.active_tabs = {}
       
        self.defaults = ["ALL"] + self.gui.RD.get_hive_types() 
        self.current_hive = ""

        self.orig_click_handler = ""

    # get plugins to run after button is clicked
    def _get_plugin_names(self):
        # the plugins to be run
        plugins = []

        selected_plugins = self.gui.pluginListWidget.selectedItems()

        if len(selected_plugins) == 0:
            self.gui.msgBox("No plugin was selected to be run.")
            return selected_plugins

        # all the user choosen plugins
        for item_w in selected_plugins:
            plugin_name = unicode(item_w.text())
            plugins.append(plugin_name)

        return plugins

    # clicked from indiviual plugin output forms 
    def createReportClicked(self):
        self.gui.createReportClicked("Plugin Single")

    def _get_label_text(self, plugin, filepath):
        return "Results for running %s against %s" % (plugin, filepath)

    def generate_plugin_results_tab(self, result):   
        # generate form for output
        tab = self.gf.plugin_export_form(self, result.fileid, result.plugin.pluginname, self._get_label_text(result.plugin.pluginname, result.filepath)) 
        
        tab.tblWidget.resizeColumnsToContents()
       
        return tab
 
    # called when run plugin button is clicked 
    def run_plugin(self):
        # a list of template instances to run
        plugin_names = self._get_plugin_names()
        
        if plugin_names == []:
            return
        
        perform_diff = self.gui.pluginDiffCheckBox.isChecked()
        
        plugin_results = self.gui.RD.plugins.run_plugins(plugin_names, perform_diff)    

        self.gui.RD.plugins.write_plugin_results(plugin_results)

        self.gui.reset_gui()
        
    # add an item to a combo box
    def _addItem(self, box, val, userdata=None):
        self.gui.__getattribute__(box).addItem(QString(val), QVariant(userdata))

    # currently only used for plugins list
    def _addListItem(self, list_widget_name, val, userdata=None):
        list_w = self.gui.__getattribute__(list_widget_name)

        # get the list item
        item = QListWidgetItem(QString(val))

        if userdata:
            item.setToolTip(QString(userdata.description))

        # add into the list
        list_w.addItem(item)
        
    def _fill_hive_combobox(self):
        self._addItem("hiveComboBox", "ALL")

        for reg_type in self.gui.RD.get_hive_types():
            self._addItem("hiveComboBox", reg_type)

    # updates the current hive
    # redraws to reflect
    def update_hive(self, index):
        hive_text = unicode(self.gui.hiveComboBox.currentText())
        if hive_text:
            self.current_hive = hive_text            
        else:
            self.current_hive = ""
    
        self._fill_plugin_listwidget()

    def _fill_plugin_listwidget(self):
        widgetname = "pluginListWidget"
        self.gui.pluginListWidget.clear()

        # set the registry types
        if self.current_hive in ["", "ALL"]:
            for i in self.defaults:
                self._addListItem(widgetname, i)
        else:
            self._addListItem(widgetname, self.current_hive)

        self.gui.RD.plugins.load_plugins()
        # set the plugins for the hive type or list all
        templates = self.gui.RD.plugins.get_loaded_plugins()

        ts = {}

        for t in templates:
            if self.current_hive in ["", "ALL"] or self.current_hive in t.hives:
                ts[t.pluginname] = t 

        # plugins in abc order
        for tname in sorted(ts.keys()):
            t = ts[tname]

            self._addListItem(widgetname, tname, t)

    def _fill_file_tree(self):
        self.fileinfo_hash = self.gcommon.fill_tree(self.gui, "pluginFilestreeWidget")

    def draw(self):
        # don't change the order...
        self._fill_hive_combobox()
        self._fill_plugin_listwidget()
        self._fill_file_tree()             

    def diffBoxClicked(self, isChecked):
        self.gcommon.diffBoxClicked(self, isChecked, "pluginDiffTreeWidget")

