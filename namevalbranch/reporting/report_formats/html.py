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

    return htmlReport()

class htmlReport:

    def __init__(self):
        self.name       = "HTML"
        self.extension  = "html"
        self.fileoutput = 1

    def set_file(self, filename):

        self.fd = codecs.open(filename, "a+", encoding="UTF-8")

    def set_table_size(self, rowmax, colmax):
        pass

    def start_output(self):
        self.fd.write("<html><head><title>Registry Decoder Report</title></head><body>")

    def start_table(self):
        self.fd.write("<table border='1'>")

    def start_column(self):
        self.fd.write("<tr>")

    def end_column(self):
        self.fd.write("</tr>")

    def write_number_column(self):
        self.fd.write("<td><b>Number</b></td>")

    def write_table_headers(self, header_list):

        for header in header_list:
            self.fd.write("<td><b>%s</b></td>" % header)
        
    def write_data_list(self, data_list, print_row, bold=-1):
            
        row = 1
        
        for outer_list in data_list:

            self.fd.write("<tr>")

            if print_row:
                self.fd.write("<td>%d</td>" % row)

            vidx = 0

            # actual report items
            for val in outer_list:
                
                if not val or val == "":
                    val = "&nbsp;"

                if vidx == bold:
                    val = "<b>" + val + "</b>"

                self.fd.write("<td>%s</td>" % val)
            
                vidx = vidx + 1

            self.fd.write("</tr>")        
                
            row = row + 1                

    def end_table(self):
        self.fd.write("</table><br /><br /><br />")

    def end_output(self):
        self.fd.write("</body></html>")
    
    def close_report(self):
        self.fd.close()

    
 

   
