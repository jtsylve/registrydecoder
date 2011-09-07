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
from xlwt import Workbook

def get_instance():

    return xlsReport()

class xlsReport:

    def __init__(self):

        self.name       = "XLS"
        self.extension  = "xls"
        self.fileoutput = 1

        self.wb        = None
        self.cur_sheet = 1

        # this is set to avoid information about term etc
        self.no_case_info = 1
 
    def set_file(self, filename):
        self.filename = filename
    
        if not self.wb:
            self.wb    = Workbook()

        self.sheet     = self.wb.add_sheet("Registry Decoder Report Sheet %d" % self.cur_sheet) 
        self.cur_sheet = self.cur_sheet + 1

    def set_table_size(self, rowmax, colmax):
        self.rmax = rowmax
        self.cmax = colmax

    def start_output(self):
        pass

    def start_table(self):
        pass

    def start_column(self):
        pass

    def end_column(self):
        pass

    def write_number_column(self):
        pass

    # we don't support headers now (not sure whats the point??)
    def write_table_headers(self, header_list):
        pass   
 
    def write_data_list(self, data_list, print_row, bold=-1):
           
        row = 0
        
        self.end_column()        

        for outer_list in data_list:

            self.start_column()

            # we dont number the rows since excel does that for you...

            col = 0

            # actual report items
            for val in outer_list:
   
                if not val:
                    val = "" 
   
                self.sheet.write(row, col, unicode(val))
 
                col = col + 1

            self.end_column()       
                
            row = row + 1                

    def end_table(self):
        pass

    def end_output(self):
        pass
 
    # save the file and then reset our variable
    def close_report(self):
        self.wb.save(self.filename)
        self.wb = None
        self.cur_sheet = 1 
 





