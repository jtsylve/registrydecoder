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

import generate_forms

class reportactions:

    def _get_report_fields(self, tab):
        report_format   = unicode(tab.cbox.currentText())
        report_filename = unicode(tab.reportname.text())
    
        return (report_format, report_filename)

    # this needs to figure out the 'tab' to call the real export_report with
    def gui_export_report(self, finfoTab, dataTab, cinfo, append=0, report_format=None, report_filename=None):
        ret = False

        try:
            t  = finfoTab.active_tabs[dataTab]
        except:
            # ugly hack b/c we add things last minute x)
            act_tabs = dict(self.plugintab.active_tabs.items() + self.searchtab.active_tabs.items() + self.pathtab.active_tabs.items())
            t = act_tabs[dataTab]
        
        if report_format == None:
            (report_format, report_filename) = self._get_report_fields(dataTab)    
 
        if report_filename == "":
            self.msgBox("No report filename given.")
        else:
            report_format = report_format.upper()
            ########################################
            # this is terrible, but would require some serious re-engineering to fix
            # we borrow the report manager instance from search (arbitrary) in order to have all the variables etc setup
            # this is the problem of command line just getting data and dumping it, but the GUI has to hold on to it until report is clicked
            # this means the report is not tied to any particular analysis type, unlike how it used to be before the cmdline/gui split and unlike how the cmdline operates
            #######################################
            self.RD.search.rm.write_results(dataTab, t.tm, t.header_info.fileid, t.header_info.action, t.header_info.context, t.header_info.term, append, report_format=report_format, report_filename=report_filename) 
            ret = True
        
        return ret
         
    # clicked from indiviual plugin output forms 
    def createReportClicked(self, context):
        currentTab = self.analysisTabWidget.currentWidget()

        successful = self.gui_export_report(currentTab.analysis_tab, currentTab, 1, append=0)

        if successful:
            self.msgBox("Report Successfully Created") 

    # called when Export All is clicked on a bulk export tab
    def exportAll(self):
        ####### break out report_format / report_name from gui_export_report if needed
        currentTab = self.analysisTabWidget.currentWidget() 
       
        if not hasattr(currentTab, "active_tabs"): 
            self.msgBox("Export All clicked when no tabs were active")
            return

        (report_format, report_filename) = self._get_report_fields(currentTab)

        extabs = currentTab.active_tabs

        # bulk export
        if not extabs:
            extabs = dict(self.searchtab.active_tabs.items() + self.plugintab.active_tabs.items() + self.pathtab.active_tabs.items())

        if len(extabs) == 0: 
            self.msgBox("Export All clicked when no tabs were active")
            return
            
        # don't export diff tabs
        remove = []
        for tab in extabs:
            if hasattr(tab, "diff_tab"):
                remove.append(tab)

        for t in remove:
            del extabs[t]
                
        i = 0
        num = len(extabs)
        # for each active tab
        for tab in extabs:
            if hasattr(tab, "do_not_export"):
                continue
        
            cinfo = not i
            append = i == num - 1
            sucess = self.gui_export_report(currentTab, tab, cinfo, append=append, report_format=report_format, report_filename=report_filename)
            i = i + 1
        
        if sucess:
            self.msgBox("Report Successfully Created") 
        else:
            self.msgBox("No Report Created. No Active Analysis Tabs were found.")

    # called when the menu report plugin is clicked, loads form that allows for exporting
    def saveAll(self, active_tabs, header):
        # generate form
        gf  = generate_forms.generate_forms(self)
        tab = gf.export_all_form(self, header)

        tab.active_tabs = active_tabs        

        # switch GUI view to it
        self.analysisTabWidget.setCurrentWidget(tab)

    def saveAllPlugins(self, isChecked):    
        self.saveAll(self.plugintab.active_tabs, "Bulk Plugin Export")

    def saveAllSearches(self, isChecked):
        self.saveAll(self.searchtab.active_tabs, "Bulk Search Export")

    def saveAllPaths(self, isChecked):
        self.saveAll(self.pathtab.active_tabs, "Bulk Path Export")

    # saves all active tabs
    def savePluginsSearches(self, isChecked):
        self.saveAll(None, "Bulk Search, Plugin, and Path Export")

        

   
