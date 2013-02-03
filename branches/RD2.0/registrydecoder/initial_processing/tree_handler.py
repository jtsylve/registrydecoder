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
import cPickle, os, sys, traceback

import registrydecoder.registryparser.regparser as regparse
from registrydecoder.errorclasses import *

class tree_handling:

    def __init__(self):
        self.reg_parser = regparse.regparser()

    def add_file_to_tree(self, gui, existingfilepath, fileid, case_obj, filepath):
        # had to try/expect whole function b/c
        # exception occurs in 'for' due to being generator
        try:
            # get the keys from the registry
            keylist = self.reg_parser.parse_file(existingfilepath)
            self.add_elements(keylist, gui, fileid, case_obj)
            error = 0
        # regfi throws generic Exception
        except Exception, e:
            error = 1

        if error: 
            print "Unable to process %s" % existingfilepath
            return False

        return True

    def add_elements(self, keylist, gui, fileid, case_obj):
        ktree = case_obj.tree
        
        i = 0
        for element in keylist:
            isroot = not i

            ktree.add_path(fileid, element, isroot)
            
            i = i + 1

            if i % 10000 == 0:
                case_obj.stringtable.commit_db()
                case_obj.vtable.conn.commit()
            
        case_obj.vtable.conn.commit()
        case_obj.stringtable.commit_db()
                
