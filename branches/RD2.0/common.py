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
import sys, os, sqlite3, getopt

from datetime import date, datetime

import common

import opencase

import template_manager as tmmod

def usage():

    print "python opencase.py <case directory> <plugin name> <file id> <extra plugin directory (optional)>"
    print "See the instructions file for complete description"
    sys.exit(1)

def parse_cmdline(gui, args):

    try:
        opts, args = getopt.getopt(sys.argv[1:], "d:", ["directory="])
    except getopt.GetoptError, err:
        print "usage: python guimain.py"
        print "optional argument: (-d/--directory) to specify an extra plugin directory"
        sys.exit(1)

    directories = ""
   
    for o, a in opts:

        if o in ("-d", "--directory"):  
            directories = a


    if directories:
        gui.plugin_dirs = directories.split(";")
    else:
        gui.plugin_dirs = []
         
def connect_db(directory, db_name):

    dbname = os.path.join(directory, db_name)
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()

    return (conn, cursor)

def die(str):

	print "FATAL: %s" % str
	sys.exit(1)

hive_types =  ["SOFTWARE", "SYSTEM", "SECURITY", "NTUSER", "SAM", "USRCLASS"]

def plugin_cmdline():

    try:
        case_dir    = sys.argv[1]
        plugin_name = sys.argv[2]
        fileid      = int(sys.argv[3])
    except:
        usage()

    try:
        extra = sys.argv[4]
        extra = extra.split(";") 
    except:
        extra = []

    # open the case and get the tree
    o = opencase.opencase(case_dir)
    o.current_fileid = fileid

    tm = tmmod.TemplateManager()
    tm.load_templates(o, extra)
    
    templates = tm.get_loaded_templates()
    
    ran = 0
    
    for t in templates:
        if t.pluginname == plugin_name:
            t.run_me()
            ran = 1
            break

    if ran:
        print "------output for %s------" % plugin_name
        
        for val_list in tm.report_data:
            for val in val_list:
                print val,
            print ""

    else:
        print "invalid plugin given" 


