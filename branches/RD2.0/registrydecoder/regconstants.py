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
#handles communication between gui and processing code

# evidence types
UNKNOWN = 0
DD  = 1
RDB = 2
SINGLEFILE = 3
MEMORY = 4

# DO NOT CHANGE THIS OR THE HASH TABLE
# registry types
SOFTWARE = 1
SYSTEM   = 2
SECURITY = 3
NTUSER   = 4
SAM      = 5
USRCLASS = 6
HARDWARE = 7
SECCLONE = 8

hive_types =  ["SOFTWARE", "SYSTEM", "SECURITY", "NTUSER", "SAM", "USRCLASS", "HARDWARE", "SECCLONE"]
registry_types = {SOFTWARE: "SOFTWARE", SYSTEM: "SYSTEM", SECURITY:"SECURITY", NTUSER:"NTUSER", SAM:"SAM", USRCLASS:"USRCLASS", HARDWARE:"HARDWARE", SECCLONE:"SECCLONE"}


