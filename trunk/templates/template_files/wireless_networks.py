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
# Wireless Networks 
# ver 1.0 
# 07/18/2011

pluginname = "Wireless Networks"
description = "Displays info on connections to wireless networks."
hive = "SOFTWARE"    
documentation = ""

    
def run_me():

    regkey = reg_get_required_key("\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
    subkeys = reg_get_subkeys(regkey)
	
    for key in subkeys:
        values = reg_get_values(key)

        for val in values:
            name = reg_get_value_name(val)
            if name == "DateCreated" or name == "DateLastConnected":
                data = reg_get_raw_value_data(val)
                data = pretty_date128(data)
            else:
                data =  reg_get_value_data(val)

            reg_report((name, data))


