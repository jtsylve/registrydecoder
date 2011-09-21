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

name       = "Default Screen Display"
fileoutput = 0

def get_instance():

    return screenDisplay()

class screenDisplay:

    def __init__(self):
        self.name       = name
        self.fileoutput = fileoutput


    def report_data(self, tableWidget, header_list, data_list, match_idxs, rowmax, colmax, color_idxs):
        
        tableWidget.setRowCount(rowmax)
        tableWidget.setColumnCount(colmax)
        tableWidget.setHorizontalHeaderLabels(header_list)

        row = 0

        if color_idxs == []:
            colors = [Qt.black, Qt.black, Qt.black]
            idxctr = -1
        else:
            colors = [Qt.red, Qt.black, Qt.blue]
            idxctr = color_idxs[0] 
            #if idxctr > 0:
            #    idxctr = idxctr - 1

        color_idx = 0 
        color = colors[color_idx]

        # first list
        for outer_list in data_list:
        
            if color_idxs != [] and idxctr == 0:
                if color_idx < 2:
                    color_idx = color_idx + 1
                #print "new color idx %d" % color_idx
                idxctr    = color_idxs[color_idx]# - 1
                #print "set1 %d" % idxctr
    
                if idxctr == 0:        
                    if color_idx < 2:
                        color_idx = color_idx + 1

                    idxctr    = color_idxs[color_idx]
                    #print "Set2: %d" % idxctr

                #print "trying idx color %d" % color_idx
                
                color     = colors[color_idx]
            
            col = 0

            if match_idxs and match_idxs != []:
                idx = match_idxs[row]
            else:
                idx = -1
        
            # actual report items
            for val in outer_list:
        
                item = QTableWidgetItem(QString(val))

                if col == idx:
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                
                fg = item.foreground()
                fg.setColor(color)
                item.setForeground(fg)

                tableWidget.setItem(row, col, item)

                col = col + 1            

            row = row + 1
               
            idxctr = idxctr - 1


        tableWidget.resizeColumnsToContents()
     
   

















