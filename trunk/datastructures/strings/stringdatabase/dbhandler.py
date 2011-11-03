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

import sqlite3handler

class dbhandler:

    def __init__(self, dbtype, case_dir):

        self.databases = { "sqlite3" : sqlite3handler.sqlite3class    }

        self.handle = self.set_dbhandle(dbtype, case_dir)

    def get_dbhandle(self):

        return self.handle

    def set_dbhandle(self, dbtype, case_dir):

        if dbtype in self.databases:
            ret = self.databases[dbtype](case_dir)
        else:
            print "Invalid database type sent to get_dbhandle %s" % dbtype
    
        return ret


