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
import sys, os, sqlite3

from datetime import date, datetime

def connect_db(directory, db_name):

    dbname = os.path.join(directory, db_name)
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()

    return (conn, cursor)

def die(str):

	print "FATAL: %s" % str
	sys.exit(1)

hive_types =  ["SOFTWARE", "SYSTEM", "SECURITY", "NTUSER", "SAM", "USRCLASS"]


