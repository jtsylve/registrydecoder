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

pluginname = "Windows Version"
description = "Display inofrmation on exact Windows version installed."
hive = "SOFTWARE"    
documentation = ""

    
def run_me():

    regkey = reg_get_required_key("\Microsoft\Windows NT\CurrentVersion")
    reg_set_report_timestamp(reg_get_lastwrite(regkey))

    fields = ["ProductName", "CSDVersion", "BuildName", "BuildNameEx", "InstallDate"]

    for val in reg_get_values(regkey):
        valname = reg_get_value_name(val) 
        if valname in fields:
            if valname == "InstallDate":
                reg_report((valname, pretty_unixtime(reg_get_value_data(val))))
            else:
                reg_report((valname, reg_get_value_data(val)))





