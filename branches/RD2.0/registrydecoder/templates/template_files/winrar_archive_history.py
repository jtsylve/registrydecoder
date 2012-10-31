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
# Kevin Moore - km@while1forensics.com
# Version 0.1
#
#

pluginname = "WinRAR Archive History"
description = "Provides information on recent WinRAR archives and extraction locations"
hive = "NTUSER"    
documentation = ""
    
def run_me():

    def process_subkeys(subkeys):
        
        for sub in subkeys:
        
            key = reg_get_key_name(sub)
            
            if key == 'ArcHistory':
                
                reg_report(('Archive History'))
                reg_report_values_name_data(sub)
                reg_report((''))
            
            elif key == 'DialogEditHistory':
                
                reg_report(('Dialog Edit History'))
                
                new_key = reg_get_required_key("\Software\WinRAR\DialogEditHistory")
                reg_report_values_name_data(new_key)
                subsub_keys = reg_get_subkeys(new_key)
                
                for sk in subsub_keys:
                    
                    reg_report(reg_get_key_name(sk))
                    reg_report_values_name_data(sk)       
                
                reg_report((''))
                    
    # END FUNCTION process_subkeys
                
    try:
        regkey = reg_get_required_key("\Software\WinRAR")
        subkeys = reg_get_subkeys(regkey)
        process_subkeys(subkeys)
    
    except:
        reg_report(('WinRAR Folder Not Identified in Registry File'))