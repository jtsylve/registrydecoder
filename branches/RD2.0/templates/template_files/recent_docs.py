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

pluginname = "Recent Docs"
description = "Displays files and folders recently accessed by this user."
hive = "NTUSER"    

    
def run_me():

    regkey = reg_get_required_key("\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
    values = reg_get_values(regkey)

    for val in values:
        name = reg_get_value_name(val)
        data = reg_get_value_data(val)
        if name == "MRUListEx" and data:
            if len(data) == 1:
                data = ord(data)
            
        reg_report((name, data))

