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
# Updated 03/09/12
# Kevin Moore - km@while1forensics.com
#

pluginname = "MUI Cache"
description = "Displays executables from user MUICache key"
hives = ['NTUSER', 'USRCLASS']  
documentation = ""

    
def run_me():

    def process_key(regkey):
        
        reg_set_report_timestamp(reg_get_lastwrite(regkey))
    
        for val in reg_get_values(regkey):
            if reg_get_value_name(val) is not "LangID":
                reg_report((reg_get_value_name(val), reg_get_value_data(val)))
                
    if path_exists(root_key() + '\Local Settings\Software\Microsoft\Windows\shell\MUICache'):  # USRCLASS
        
        regkey = reg_get_required_key('\Local Settings\Software\Microsoft\Windows\shell\MUICache')
        process_key(regkey)
        
    elif path_exists(root_key() + '\Software\Microsoft\Windows\ShellNoRoam\MUICache'):         # NTUSER
        
        regkey = reg_get_required_key("\Software\Microsoft\Windows\ShellNoRoam\MUICache")
        process_key(regkey)
        
    else:
        reg_report(('MUICache not found in registry file'))
    
    
        




