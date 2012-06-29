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
# Recent Docs
# ver 1.0 
# 07/18/2011
#
# Updated by Kevin Moore - CERT - kevinm@cert.org
# 11/04/2011

pluginname = "Recent Docs Ordered"
description = "Displays files and folders recently accessed by this user and ordered by their associated MRUListEx value"
hive = "NTUSER"    
    
def run_me():
    
    def chunks(l, n):
        list = []
        for i in range(0, len(l), n):
            list.append(str(l[i:i+n]))
        return list
    
    def parse_mrulistex(name, data):
        
        import struct
        
        mru_order = []      
        ptr = 0
        
        while data[ptr:ptr+4] != '\xFF\xFF\xFF\xFF':                                   # Each MRUListEx entry is 4 bytes (uint) and \xFF\xFF\xFF\xFF signifies the end of the entries data
            
            mru, = struct.unpack('I', data[ptr:ptr+4])                                 # Iterate through the file and gather a list of integer values
            mru_order.append(mru)
            ptr += 4
                    
        return mru_order                                                               # Return the order list so we can compare the values to our RecentDocs entries
    
    # END FUNCTION - parse_mrulistex
    
    def get_values(key):
        
        entry_values = {}
        
        reg_entries = reg_get_values(key)
    
        for val in reg_entries:
            
            name = reg_get_value_name(val)
            
            if name == 'MRUListEx':                                                     # MRUListEx provides an ordered list of when RecentDocs entries were accessed
                data = reg_get_raw_value_data(val)                                      # Need raw value data to read MRUList entry values
                order = parse_mrulistex(name, data)                                     # Gathers a list of ordered entry values (number to associate RecentDocs values)
                split_mrulist = chunks(order, 20)
                reg_report(('MRUListEx Order: ', '\n'.join(split_mrulist)))                            # Prints a list of the MRUListEx ordered list for reference)
            else:
                data = reg_get_value_data(val)
                entry_values[int(name)] = data                                          # If the data is not a list add to a dictionary for reference, key value of dictionary is integer of Recent Docs entry
        
        for i in order:
            try:
                reg_report((entry_values[i],str(i)))                                    # Once we have gathered an order list and all our RecentDocs values, print them out in the order in which they were last accessed
            except:
                reg_report(('***ERROR: Unidentified MRUList Entry', str(i)))            # Not sure if this can happen, but don't want to the script to stop processing if it does
         
        reg_report((''))   
    # END FUNCTION - get_values
    
    # Start of Plugin's processing...
                
    key_path = "\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    key = reg_get_required_key(key_path)    
    report((key_path, reg_get_lastwrite(key)))                                          # Header format for each RecentDocs folder is: RegistryPath, LastWrittenDate  
    get_values(key)                                                                     # Get Root Entries under RecentDocs folder
    
    subkeys = reg_get_subkeys(key)                                                      # RecentDocs folder sometimes contains subfolders
    
    for key in subkeys:
        
        report((key_path + "\\" + reg_get_key_name(key), reg_get_lastwrite(key)))       # Subfolder report value header: RegistryPath, LastWrittenDate 
        get_values(key)                                                                 # Get Values from Subkey


