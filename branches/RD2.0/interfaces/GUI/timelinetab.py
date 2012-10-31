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
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

import datetime, codecs

class timeline_params:
    def __init__(self, outputfile, ext, startDate, endDate):
        self.outputfile = outputfile
        self.ext        = ext
        self.startDate  = startDate
        self.endDate    = endDate

class timelinetab:

    def __init__(self, gui):
        self.name = "Path Tab"
        self.active_tabs = {}

        self.gui = gui

    def draw(self):
        self.info_hash = self.gcommon.fill_tree(self.gui, "timelineTreeWidget")  

    def timeline_output_browse(self):    
        filename = QFileDialog.getSaveFileName(directory="/home/x/RDNIST/source", filter="All (*)", parent=self.gui, caption="Timeline Output File") 
        self.gui.timelineLineEdit.setText(filename)

    def _get_timeline_params(self):
        outputfile = self.gui.timelineLineEdit.text()
    
        if not outputfile:
            self.gui.msgBox("No output file was entereted!")
            return None

        outputfile = unicode(outputfile)
        
        if len(outputfile) == 0:
            self.gui.msgBox("No output file was entereted!")
            return None

        if self.gui.excelRadioButton.isChecked():
            ext = ".tsv"
        else:
            ext = ".txt"

        startDate    = str(self.gui.timelineStartDateLineEdit.text())
        endDate      = str(self.gui.timelineEndDateLlineEdit_2.text())
            
        return self.gui.RD.timeline.set_timeline_params(outputfile, ext, startDate, endDate)
        
    # called when 'timeline' is clicked
    def viewTree(self):
        tp = self._get_timeline_params()

        if not tp or tp == None:
            return

        self.gui.RD.timeline.write_timeline(tp)

        self.gui.reset_gui() 

