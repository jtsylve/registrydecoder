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
# Kevin Moore - km@while1forensics.com
# Version 0.1
#

pluginname = "Mapped Network Drive Letters"
description = "Lists user's mapped network drives according to volume letter"
hive = "NTUSER"    
documentation = ""
    
def run_me():

    regkey = reg_get_required_key("\Network")
    subkeys = reg_get_subkeys(regkey)
    
    for key in subkeys:
        reg_report(('Drive Letter', reg_get_key_name(key)))
        reg_report(('Last Written Date', reg_get_lastwrite(key)))
        reg_report_values_name_data(key)
        reg_report((''))




