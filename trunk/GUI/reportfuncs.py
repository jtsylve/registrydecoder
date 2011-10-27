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

class report_handler:

    def __init__(self, gui, active_tabs, rm, gf):
        self.gui         = gui
        self.active_tabs = active_tabs 
        self.rm          = rm
        self.gf          = gf

    def get_plugin_export_format(self, cbox):

        name = unicode(cbox.currentText())
        return self.rm.report_hash[name]
 
    def get_filename(self, lineedit):

        fname = lineedit.text()
        return str(fname)
           
    def export_report(self, finfoTab, dataTab, cinfo, append=0):

        # information about tab being processed
 
        try:
            tab_info    = self.active_tabs[dataTab]
        except:
            # ugly hack b/c we add things last minute x)
            act_tabs = dict(self.gui.plugintab.rh.active_tabs.items() + self.gui.searchtab.rh.active_tabs.items() + self.gui.pathtab.rh.active_tabs.items())
            tab_info = act_tabs[dataTab]
            
        report   = self.get_plugin_export_format(finfoTab.cbox)
        repext   = "." + report.extension

        filename = self.get_filename(finfoTab.reportname) 
        
        if not filename or len(filename) == 0:
            self.gui.msgBox("Create Report button clicked but no report filename was given. Cannot Proceed.")
            return None
              
        # if the user didn't supply an extension, then append it (given from report module)
        if not filename.endswith(repext):
            filename = filename + repext

        report.report_single(report, filename, tab_info, cinfo)

        if append == 0:
            report.close_report()

        return report

    def saveAllPlugins(self, isChecked):    

        self.saveAll(self.gui.plugintab.active_tabs, "Bulk Plugin Export")

    def saveAllSearches(self, isChecked):

        self.saveAll(self.gui.searchtab.active_tabs, "Bulk Search Export")

    def saveAllPaths(self, isChecked):

        self.saveAll(self.gui.pathtab.active_tabs, "Bulk Path Export")

    # saves all active tabs
    def savePluginsSearches(self, isChecked):

        #self.saveAll(dict(self.gui.searchtab.active_tabs.items() + self.gui.plugintab.active_tabs.items() + self.gui.pathtab.active_tabs.items()), "Bulk Search, Plugin, and Path Export")
        self.saveAll(None, "Bulk Search, Plugin, and Path Export")

    # called when the menu report plugin is clicked, loads form that allows for exporting
    def saveAll(self, active_tabs, header):
        
        # generate form
        tab = self.gf.export_all_form(self, header)

        tab.active_tabs = active_tabs        

        # switch GUI view to it
        self.gui.analysisTabWidget.setCurrentWidget(tab)
    
    # called when Export All is clicked on a bulk export tab
    def exportAll(self):
    
        currentTab = self.gui.analysisTabWidget.currentWidget() 
        
        if not hasattr(currentTab, "active_tabs"): 
            self.gui.msgBox("Export All clicked when no tabs were active")
            return

        extabs     = currentTab.active_tabs

        # bulk export
        if not extabs:
            extabs = dict(self.gui.searchtab.active_tabs.items() + self.gui.plugintab.active_tabs.items() + self.gui.pathtab.active_tabs.items())

        if len(currentTab.active_tabs) == 0: 
            self.gui.msgBox("Export All clicked when no tabs were active")
            return

        report     = self.get_plugin_export_format(currentTab.cbox)

        i = 0

        # for each active tab
        for tab in extabs:
        
            if hasattr(tab, "do_not_export"):
                continue
        
            cinfo = not i
            repinst = self.export_report(currentTab, tab, cinfo, 1)
            i = i + 1
        
        if repinst:
            repinst.close_report()
         
        self.gui.msgBox("Report Successfully Created") 

    # clicked from indiviual plugin output forms 
    def createReportClicked(self, context):

        currentTab = self.gui.analysisTabWidget.currentWidget()

        #if currentTab in self.active_tabs:
        self.export_report(currentTab, currentTab, 1)

        self.gui.msgBox("Report Successfully Created") 

