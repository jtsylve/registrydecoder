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

import initial_processing.create_case

import opencase

import analysis.search    as searchAnalysis
import analysis.plugins   as pluginsAnalysis
import analysis.timeline  as timelineAnalysis
import analysis.pathbased as pathbasedAnalysis
import analysis.hivebrowser as hiveBrowser

import report_manager as rpmod 

import regconstants

import handle_file_info

import common

class registrydecoder:
    def __init__(self, UI):
        # reference to the user interface
        self.UI = UI

        # creating a csae
        self.createcase = initial_processing.create_case.create_case(UI)

        # opening a case
        self.opencase = opencase.opencase(UI)
       
        # reference to reports for names
        self.ref_rm = rpmod.report_manager(self)
 
        self.handle_file_info = handle_file_info

        # analysis classes (search, timeline, etc)
        self.search    = searchAnalysis.searchAnalysis(UI)
        self.plugins   = pluginsAnalysis.pluginAnalysis(UI)
        self.timeline  = timelineAnalysis.timelineAnalysis(UI)
        self.pathbased = pathbasedAnalysis.pathbasedAnalysis(UI)
        self.hivebrowser = hiveBrowser.hiveBrowser(UI)

    # hives as a list
    def get_hive_types(self):
        return regconstants.hive_types   
     
    # hash table of hive number to type (str)
    def get_registry_types(self):
        return regconstants.registry_types

    def get_file_info(self, file_hash, fileid, extra=0):
        return common.get_file_info(file_hash, fileid, extra)




