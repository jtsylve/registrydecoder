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
# creates HTML formatted output

import codecs

def get_instance():

    return csvReport()

class csvReport:

    def __init__(self):
        self.name       = "CSV"
        self.extension  = "csv"
        self.fileoutput = 1

    def set_file(self, filename):

        self.fd = codecs.open(filename, "a+", encoding="UTF-8")

    def set_table_size(self, rowmax, colmax):
        pass

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

    def write_table_headers(self, header_list):
        pass
        
    def write_data_list(self, data_list, print_row, bold=-1):
            
        row = 1
        
        # don't write out case info & headers
        if print_row == 0:
            return

        for outer_list in data_list:

            if print_row:
                self.fd.write("%d," % row)

            vidx = 0

            # actual report items
            for val in outer_list:
                
                if not val or val == "":
                    val = ""

                val = val.replace(",", "<COMMA>")

                self.fd.write("%s," % val)
            
                vidx = vidx + 1

            self.fd.write("\n")        
                
            row = row + 1                

    def end_table(self):
        pass

    def end_output(self):
        pass
 
    def close_report(self):
        self.fd.close()

    
 

   
