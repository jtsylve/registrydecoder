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

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

import datetime, codecs

class timeline_params:

    def __init__(self, fd, outputfile, startDate, endDate):

        self.fd         = fd
        self.outputfile = outputfile
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
        filename = QFileDialog.getSaveFileName(directory="/home/x/", filter="All (*)", parent=self.gui, caption="Timeline Output File") 
        
        self.gui.timelineLineEdit.setText(filename)

    def get_timeline_params(self):
       
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

        if not outputfile.endswith(ext):
            outputfile = outputfile + ext
 
        try:
            fd = codecs.open(outputfile, "a+", encoding="UTF-8")
        except:
            self.gui.msgBox("Unable to open output file for writing!")
            return None

        startDate    = self.gui.timelineStartDateLineEdit.text()
        endDate      = self.gui.timelineEndDateLlineEdit_2.text()
        
        if startDate != "":
            s = self.gcommon.parse_date(self, startDate, "start")
        else:
            s = 1
        
        if endDate != "":
           e = self.gcommon.parse_date(self, endDate, "end")
        else:
           e = 1
    
        # input error
        if s == None or e == None:
            ret = None
        else:
            ret = timeline_params(fd, outputfile, startDate, endDate)
            
        return ret
        
    def run_timeline(self, fileid, sp):

        filepath = self.gcommon.get_file_info(self.info_hash, fileid)[0]

        # walk each node of the tree looking for entries that belong to this fileid
        nodehash = self.tapi.tree.nodehash

        numnodes = len(nodehash)

        for idx in xrange(0, numnodes+2):

            idx = "%d" % idx

            if idx in nodehash:
                node = nodehash[idx]
            else:
                continue

            # ensure fileid is correct
            if fileid in node.fileids:
  
                # filter by dates 
                if sp.startDate or sp.endDate:
                    res = self.gcommon.filter_results(self, [node], fileid, sp.startDate, sp.endDate)
                else:
                    res = [1]

                if len(res) == 1:

                    path      = self.tapi.full_path_node_to_root(node)
                    
                    lastwrite = node.timestamps[fileid] 
            
                    if self.gui.excelRadioButton.isChecked():
                        lastwrite = datetime.datetime.fromtimestamp(lastwrite).strftime('%Y/%m/%d %H:%M:%S')
                        sp.fd.write("%s\t%s\t%s\n" % (filepath, path, lastwrite))
                    
                    else:
                        # these three lines will write out autopsy format, regtime.pl
                        filepath = filepath.replace("|", ",")
                        sp.fd.write("0|%s:%s|0|0|0|0|0|0|%d|0|0\n" % (filepath, path, lastwrite))

    # called when 'timeline' is clicked
    def viewTree(self):

        sp = self.get_timeline_params()

        if not sp or sp == None:
            return

        self.gcommon.run_cb_on_tree(self, self.run_timeline, sp, "timelineTreeWidget")  
        
        sp.fd.close()

        self.gui.msgBox("Timeline Created")

        # to catch anyone pulling the stale file id
        self.gui.case_obj.current_fileid = -42
   

