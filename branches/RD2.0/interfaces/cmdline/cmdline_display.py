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

import sys

name       = "Command Line Display"

def get_instance():
    return cmdLineDisplay()

class cmdLineDisplay:
    def __init__(self):
        self.name = name
        self.sep  = " "

    def write(self, msg):
        sys.stdout.write(msg.encode('utf-8'))

    def start_report(self):
        self.write("-" * 80)

    def write_cell(self, data):
        cell_len = 40
        data_len = len(data)
        
        pad_len = cell_len - data_len

        if pad_len > 0:
            pad = self.sep * pad_len
        else:
            pad = " "

        self.write(data + pad)
        
    def end_row(self):
        self.write("\n")

    # TODO_NIST - move to common w gui
    def calc_colors(self, data_list, color_idxs):
        #print "color: %s" % str(color_idxs)

        if color_idxs == []:
            colors = [""] * len(data_list) 
        else:
            colors = "-" * color_idxs[0] + "same" * color_idxs[1] + "+" * color_idxs[2]
     
        #print colors

        return colors

    def report_data(self, _tableWidget, header_list, data_list, info_class):

        (match_idxs, rowmax, colmax, color_idxs) = (info_class.match_idxs, info_class.rows_max, info_class.cols_max, info_class.color_idxs)

        self.start_report()
        self.end_row()

        # write out the headers
        for header in header_list:
            self.write_cell(header)

        self.end_row()

        row = 0

        colors = self.calc_colors(data_list, color_idxs)

        # first list
        for (row, row_val) in enumerate(data_list):
            color = colors[row]
            if color: 
                print color,
 
            if match_idxs and match_idxs != []:
                idx = match_idxs[row]
            else:
                idx = -1
      
            # actual report items
            for (col, col_val) in enumerate(row_val):
                # this is the match of a search
                if col == idx:
                    col_val = "*" + col_val + "*"

                self.write_cell(col_val)

            self.end_row()
                    
            
