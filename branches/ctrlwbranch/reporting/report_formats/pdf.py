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
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def get_instance():

    return pdfReport()

class pdfReport:

    def __init__(self):

        self.name       = "PDF"
        self.extension  = "pdf"
        self.fileoutput = 1

        self.tables = []
    
    def set_file(self, filename):
        self.fd = SimpleDocTemplate(filename, pagesize=letter, title="Registry Decoder Report", author="Registry Decoder")

    def set_table_size(self, rowmax, colmax):
        self.rmax = rowmax
        self.cmax = colmax

    def start_output(self):
        pass

    def start_table(self):
        self.cur_col = -1
        self.report_data = {}

    def start_column(self):
        self.report_data[self.cur_col] = []

    def end_column(self):
        self.cur_col = self.cur_col + 1

    def write_number_column(self):
        self.report_data[self.cur_col].append("Number")

    def write_table_headers(self, header_list):

        for header in header_list:
            self.report_data[self.cur_col].append("%s" % header)
    
    def write_data_list(self, data_list, print_row, bold=-1):
            
        row = 1
        
        self.end_column()        

        style = getSampleStyleSheet()['Normal']
        style.wordWrap = 'LTR'

        #if not self.cur_col in self.report_data:
        #    self.report_data[self.cur_col] = []

        for outer_list in data_list:

            self.start_column()

            if print_row:
                self.report_data[self.cur_col].append("%d" % row)

            vidx = 0

            # actual report items
            for val in outer_list:
   
                if not val:
                    val = "" 
   
                val = "".join(val[i:i+40] + "\n" for i in xrange(0,len(val),40))

                #val = Paragraph(val, style)
             
                #if not val or val == "":
                #    val = "&nbsp;"
                #
                #if vidx == bold:
                #    val = "<b>" + val + "</b>"

                self.report_data[self.cur_col].append(val)
            
                vidx = vidx + 1

            self.end_column()       
                
            row = row + 1                

    def end_table(self):

        draw_data = []

        for col in sorted(self.report_data.keys()):
            draw_data.append([])

            for row in self.report_data[col]:
                draw_data[col].append(row)

        #print "drawing:\n%s\n\n" % str(draw_data)
        #print "%d | %d" % self.cmax

        t = Table(draw_data)
        t.hAlign = 'LEFT'
        t.setStyle(TableStyle([('BOX', (0,0), (-1,-1), 0.25, colors.black), ('GRID',(0,0),(-1,-1),0.5,colors.black)]))
        self.tables.append(t)

    def end_output(self):
        pass
 
    def close_report(self):
        self.fd.build(self.tables)
        self.fd = None

 
 





        



