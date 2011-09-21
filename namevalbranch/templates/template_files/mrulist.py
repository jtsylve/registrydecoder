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

pluginname = "User MRUs"
description = ""
hive = "NTUSER"    
documentation = ""

    
def run_me():

    mru_keys = (
            "\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            "\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU",
            "\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
            "\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU",
            "\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
            "\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy",
            "\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU",   
            "\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\FirstFolder" )

    ignore = ("MRUListEx")
     
    for mru_key in mru_keys:
        regkey = reg_get_key(mru_key)
        if regkey:
            reg_report((mru_key))
            for val in reg_get_values(regkey):
                if reg_get_value_name(val) not in ignore:
                    reg_report((reg_get_value_name(val), reg_get_value_data(val)))
            reg_report((""))





