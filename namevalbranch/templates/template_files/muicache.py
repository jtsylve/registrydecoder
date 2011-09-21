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
#

pluginname = "MUI Cache"
description = "Displays executables from user MUICache key"
hive = "NTUSER"    
documentation = ""

    
def run_me():

    regkey = reg_get_required_key("\Software\Microsoft\Windows\ShellNoRoam\MUICache")
    reg_set_report_timestamp(reg_get_lastwrite(regkey))

    for val in reg_get_values(regkey):
        if reg_get_value_name(val) is not "LangID":
            reg_report((reg_get_value_name(val), reg_get_value_data(val)))
        




