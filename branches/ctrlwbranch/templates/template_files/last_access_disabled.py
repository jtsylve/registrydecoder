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
# Last Access Disabled 
# ver 1.0 
# 07/18/2011

pluginname = "Last Access Disabled"
description = "Displays whether last access time filesystem timestamps are disabled."
hive = "SYSTEM"    
    

def run_me():

    regkey = reg_get_required_key("\ControlSet00"+get_current_control_set()+"\Control\FileSystem")
    found = False
    for val in reg_get_values(regkey):
        if reg_get_value_name(val) == "NtfsDisableLastAccessUpdate":
            found = True
            reg_report((reg_get_value_name(val), reg_get_value_data(val)))		
    if not found:
        reg_report("NtfsDisableLastAccessUpdate not found.")

