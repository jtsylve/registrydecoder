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
# Windows Uninstall
# Version 0.1
#
# Kevin Moore - km@while1forensics.com
# 

pluginname = "Windows Uninstall"
description = "Displays Windows compatible programs with an uninstall application or feature"
hive = "SOFTWARE"    
    
def run_me():

    def get_values(key):
        
        reg_entries = reg_get_values(key)
    
        for val in reg_entries:
            
            name = reg_get_value_name(val)
            data = reg_get_value_data(val)            
            reg_report((name,data))                                    # Once we have gathered an order list and all our RecentDocs values, print them out in the order in which they were last accessed
         
        reg_report((''))   
    # END FUNCTION - get_values
    
    # Start of Plugin's processing...
                
    key_path = "\Microsoft\Windows\CurrentVersion\Uninstall"
    key = reg_get_required_key(key_path)                                             # Header format for each RecentDocs folder is: RegistryPath, LastWrittenDate  
    
    subkeys = reg_get_subkeys(key)                                                      # RecentDocs folder sometimes contains subfolders
    
    for key in subkeys:
        
        reg_report((key_path + "\\" + reg_get_key_name(key), reg_get_lastwrite(key)))       # Subfolder report value header: RegistryPath, LastWrittenDate 
        get_values(key)                                                                 # Get Values from Subkey


