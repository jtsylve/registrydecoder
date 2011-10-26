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
import sys

from guicontroller import *

class registry_sig:


    def __init__(self):
        pass

    def determine_type(self, checkbuffer):

        lookfor = ["s\x00o\x00f\x00t\x00w\x00a\x00r\x00e\x00", "s\x00y\x00s\x00t\x00e\x00m\x00", "s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00"]
        lookfor = lookfor + ["n\x00t\x00u\x00s\x00e\x00r\x00.\x00d\x00a\x00t",  "s\x00a\x00m\x00", "u\x00s\x00r\x00c\x00l\x00a\x00s\x00s\x00.\x00d\x00a\x00t\x00"]
        lookfor = lookfor + ["U\x00s\x00r\x00C\x00l\x00a\x00s\x00s\x00.\x00d\x00a\x00t\x00"]       

        default = "D\x00E\x00F\x00A\x00U\x00L\x00T"

        idx = 1
 
        for check in lookfor:

            if check in checkbuffer or check.upper() in checkbuffer:
                    
                # UsrClass to usrclass
                if idx == 6:
                    idx = 5

                return [SINGLEFILE, idx]

            idx = idx + 1

        # default is really an ntuser file
        if default in checkbuffer or default.upper() in checkbuffer:
            return [SINGLEFILE, 6]
            
        return None

    def determine_type_file(self, filename):

        return self.determine_type(open(filename,"rb").read(0x80))

def main():

    r = registry_sig()

    res = r.determine_type_file(sys.argv[1])

    if res:
        print res #registry_types[res[1]]
    else:
        print "no"



if __name__ == "__main__":
    main()

