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
# Updated 3/9/12
# Kevin Moore - km@while1forensics.com
#
#


pluginname = "System Runs"
description = "Displays (some of the) programs that run at system startup."
hive = "SOFTWARE"    
documentation = ""
    

def run_me():

    run_keys = (
        "\Microsoft\Windows\CurrentVersion\Runonce",  
        "\Microsoft\Windows\CurrentVersion\policies\Explorer\Run",  
        "\Microsoft\Windows\CurrentVersion\Run",
        "\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
        "\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "\Policies\Microsoft\Windows\System" )  

    parse_keys = ['\Microsoft\Windows NT\CurrentVersion\Winlogon',
                  '\Policies\Microsoft\Windows\System']
    
    parse_vals = ['shell','userinit']    

    reg_set_report_header(("Key", "Name", "Path"))

    for rk in run_keys:
        
        regkey = reg_get_key(rk)
        
        if regkey:
            
            if rk in parse_keys:
                
                key = reg_get_required_key(rk)
                values = reg_get_values(key)
                
                for val in values:
                    name = reg_get_value_name(val)
                    name = name.lower()
                    
                    if name in parse_vals:
                        reg_report((rk, name, reg_get_value_data(val)))
                    
            else:
                
                values = reg_get_values(regkey)
                
                for val in values:
                    reg_report((rk, reg_get_value_name(val), reg_get_value_data(val)))





