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
# Mounted Devices
# ver 1.0 
# 07/18/2011

pluginname = "Services"
description = "Displays info on running services."
hive = "SYSTEM"    
    
svc_types =     {   0x001 : "Kernel driver",
                    0x002 : "File system driver",
                    0x010 : "Own_Process",
                    0x020 : "Share_Process",
                    0x100 : "Interactive" }

start_types =   {   0x00 : "Boot Start",
                    0x01 : "System Start",
                    0x02 : "Auto Start",
                    0x03 : "Manual",
                    0x04 : "Disabled" }


def run_me():

    reg_set_report_header(("Name","Display Name","Image Path", "Type", "Start", "Group"))    

    regkey = reg_get_required_key("\ControlSet00"+get_current_control_set()+"\services")
    subkeys = reg_get_subkeys(regkey)

    for key in subkeys:
        fields = {
            "Name"          : "", 
            "DisplayName"   : "",
            "ImagePath"     : "",
            "Type"          : "",
            "Start"         : "",
            "Group"         : ""
        }

        fields["Name"] = reg_get_key_name(key)
        values = reg_get_values(key)
        for val in values:
            name = reg_get_value_name(val)
            data = reg_get_value_data(val)
            
            
            if name in fields.keys():
                fields[name] = data
            if name == "Type":
                if data:
                    idata = int(data)
                else:
                    idata = 0
                if idata in svc_types.keys():
                    fields[name] = svc_types[idata]
            if name == "Start":
                if data:
                    idata = int(data)
                else:
                    idata = 0
                fields[name] = start_types[idata]
                
        reg_report((fields["Name"], fields["DisplayName"], fields["ImagePath"], fields["Type"], fields["Start"], fields["Group"]))
 
 






