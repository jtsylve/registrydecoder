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
# TODO: Test me on XP
#
#

import struct


pluginname = "User Assist"
description = ""
hive = "NTUSER"    
documentation = ""


ver_7_2008_ids = ("CEBFF5CD-ACE2-4F4F-9178-9926F41749EA", "F4E57C4B-2036-45F0-A9AB-443BCFE33D9F")
    

def run_me():

    regkey = reg_get_required_key("\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    subkeys = reg_get_subkeys(regkey)
    for key in subkeys:
        key_name = reg_get_key_name(key)
        key_path = "\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        key_path += "\%s\count" % key_name
        skey = reg_get_required_key(key_path)
        values = reg_get_values(skey)
        reg_report(("ID:", key_name)) 
        for val in values:
            name = rot13(reg_get_value_name(val))
            data = reg_get_value_data(val)

            if key_name in ver_7_2008_ids:
                reg_report((name, data))

            else: # pre_7_2008
                if len(data) == 16:
                    x, y, z, w = struct.unpack("IIII", data) 
                    reg_report((name, str(x), str(y), str(z), str(w)))
                else:
                    reg_report((name, data))

        report((""))


