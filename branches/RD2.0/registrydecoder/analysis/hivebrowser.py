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

import registrydecoder.analysis.base as analysisBase
import registrydecoder.common as common
import registrydecoder.handle_file_info as handle_file_info

# these are basically just helper functions for the hive browser capabilities
class hiveBrowser(analysisBase.analysisBase):
    def __init__(self, UI):
        analysisBase.analysisBase.__init__(self, UI)

    def get_current_fileids(self):
        return self.UI.get_current_fileids("filebrowser")
    
    def get_file_path(self, fileid):
        self.fileinfo_hash = handle_file_info.get_hives_info(self.UI)[0]
        return common.get_file_info(self.fileinfo_hash, fileid)
         
