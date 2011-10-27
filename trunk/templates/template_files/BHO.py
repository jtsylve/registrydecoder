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
# 
#
# Kevin Moore - CERT - kevinm@cert.org

import struct

pluginname = "Browser Helper Objects"
description = ""
hive = "SOFTWARE"    
documentation = ""

def run_me():
    
    class BHO:
        
        # Class detailing information about Browser Helper Object values
        
        def __init__(self):
            
            self.ID = ""                                    # Class ID value in form {00000000-0000-0000-0000-000000000000}
            self.path = ""                                  # Full Path to Browser Helper Object key value
            self.value = ""                                 # Will be path of BHO payload (exe, dll, activex, etc)
            self.subvalue = ""                              # Will be name of BHO                             
            self.written = ""                               # Last Written Date of BHO Registry key
            
        def set_data(self, classID, reg_path, last_written):
            
            # Sets BHO class data
            
            self.ID = classID                               
            self.path = reg_path
            self.written = last_written
            return self
        
    # ENDCLASS - BHO

    def parse_bho(regkey):
        
        # Identifies and populates Browser Helper Object data, returns BHO Class object
        
        bho = BHO()
        subval = ''
        
        key_name = reg_get_key_name(regkey)
        key_path = "\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
        key_path += "\%s" % key_name                 # ClassID
        
        skey = reg_get_required_key(key_path)
        bho.set_data(key_name, key_path, get_last_write_time(skey))
        
        return bho
    
    # ENDFUNCTION - parse_bho
    
    def parse_bho_class_ids(bhos):
        
        # Parses Data in \Classes\CLSID section of Software Hive for more detailed BHO information
        key_path = '\Classes\CLSID'
        class_key = reg_get_required_key(key_path)
        subkeys = reg_get_subkeys(class_key)
    
        keynames = {}

        for key in subkeys:

            keynames[reg_get_key_name(key)] = key            
 
        for bho in bhos:
            
            key_path = '\Classes\CLSID'
            
           # Parses each key value under \Classes\CLSID to see if it matches the ClassID of a BHO identified
            if bho.ID in keynames:
                
                key_path += '\%s' % bho.ID
                regkey = reg_get_required_key(key_path)
                
                valstr = get_value_for_node_name(regkey, "NONE")
                
                if valstr: 
                    bho.subvalue = valstr
                    
                new_subkeys = reg_get_subkeys(regkey)  
                
                for sub in new_subkeys:
                    
                    # Parsing Subkeys under ClassID
                    name = reg_get_key_name(sub)
                    
                    if name.find('InprocServer32') == 0:            # Subvalue in InprocServer32 contains fullpath to BHO payload
                        
                        key_path += '\%s' % name
                        regkey = reg_get_required_key(key_path)
                        
                        valstr = get_value_for_node_name(regkey, "NONE")

                        if valstr:

                            bho.value = valstr
                            break

    #ENDFUNCTION - parse_bho_class_ids
                                    
    def print_report(bhos):
        
        # This function prints output of Browser Helper Objects Identified
        
        reg_set_report_header(('BHO Name', 'BHO Path', 'Last Written', 'Class ID', 'Registry Path'))
        
        for b in bhos:
            
            reg_report((b.subvalue, b.value, b.written, b.ID, b.path)) # Report Format: Friendly Name, Full Path to BHO file, Parent Last Written, Class ID of BHO and Reg Full Path
            
    # ENDFUNCTION print_report
    
    # ********************* #
    # Main processing Steps
    if path_exists(root_key() + "\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"):        # Determines if path exists in some software hives it does not
        
        bho_entries = []    
        regkey = reg_get_required_key("\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects")
        subkeys = reg_get_subkeys(regkey)
        
        for key in subkeys:
            
            new_bho = parse_bho(key)                  # Identifies Browser Helper Objects in standard registry location returns BHO class object
            bho_entries.append(new_bho)
            
        parse_bho_class_ids(bho_entries)              # Identifies detailed Browser Helper Object info from ClassID in \Classes\CLSID section of Software Registry Hive
        
        print_report(bho_entries)                     # Prints report
        
    else:
        reg_report(('Path to Browser Helper Objects Not Found in Registry Hive'))
       


