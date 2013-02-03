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
import sys, os, sqlite3, codecs

from datetime import date, datetime

import common
import opencase
import template_manager as tmmod
        
def connect_db(directory, db_name):
    dbname = os.path.join(directory, db_name)
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()

    return (conn, cursor)

def die(str):
	print "FATAL: %s" % str
	sys.exit(1)

def get_file_info(fhash, fileid, extra=0):
       
    if fileid in fhash:
        finfo = fhash[fileid]
    elif extra:
        return ("", "", "", "")
    else:
        return ("", "", "")

    filepath   = finfo.reg_file
    regfile    = finfo.reg_file
    alias      = finfo.alias
    evi_file   = finfo.evidence_file
    group_name = finfo.group_name
    part_num   = finfo.part_num
    type_name  = finfo.type_name
    rpname     = finfo.rp_name    

    if group_name == "SINGLE":
        group_info = group_name
    
    elif group_name == "MEMORY":
        filepath = "%s -> %s" % (evi_file, regfile)

    else:
        group_info = "Partition %s | %s | %s" % (part_num, group_name, type_name) 
       
        if rpname:
            group_info = group_info + " | " + rpname

        filepath = "%s in %s from %s" % (filepath, group_info, evi_file)

    # if an alias was given
    if len(alias) and evi_file != alias:
        filepath = filepath + " ( %s )" % alias
    
    if extra:
        ret = (evi_file, group_info, alias, regfile)
    else:
        ret = (filepath, evi_file, group_name)

    return ret

def _parse_vals(ents, sep):
    ret = None

    e = [x for x in ents.split(sep)]

    if len(e) == 3:
        try:
            ents = [int(x) for x in e]
        except:
            pass
        else:
            # ents = (year, month, day)
            ret = ents

    return ret

# get the users date in the form of mm/dd/yyyy hh:mm:ss
# ugly to support both types
def parse_date(dateStr):
    ret = None

    dateStr = dateStr.strip()

    ents = dateStr.split(" ")
        
    # date only
    if len(ents) > 0:
        date_dmy = _parse_vals(ents[0], "/")

        if date_dmy:
            (year, month, day) = date_dmy

            # time as well
            if len(ents) == 2:
                time_info = _parse_vals(ents[1], ":")
                if time_info:
                    (hour, minutes, seconds) = time_info
    
                ret = datetime(year, month, day, hour, minutes, seconds)
                
            else:
                ret = datetime(year, month, day)

    return ret

# filter search results based on the user's choosen start and end last written dates
def filter_results(UI, results, fileid, startStr, endStr):
    # the filtered set
    ret = []

    if startStr:
        start = parse_date(startStr)
        if start == None:
            UI.msgBox("Invalid start date given.")
            return None
    else:
        start = ""

    if endStr:
        end = parse_date(endStr)
        if end == None:
            UI.msgBox("Invalid end date given.")
            return None
    else:
        end = ""

    for row in xrange(len(results)):

        r = results[row]

        # convert last written time to QDate for easy comparison to user supplied choice
        if hasattr(r, "node"):
            node = r.node
        else:
            node = r

        timestamp = node.timestamps[fileid]
        c = datetime.fromtimestamp(timestamp)

        # this allows for narrowing by both start and end or just 1 at at ime
        if start and end:
            append = start <= c <= end
        
        elif start:
            append = start <= c

        elif end:
            append = end >= c
        
        if append:
            ret.append(r)

    return ret

def get_time_for_lastwrite(lastwrite):
    return datetime.fromtimestamp(lastwrite).strftime('%Y/%m/%d %H:%M:%S')

# used to get the search/path term or terms from a file for the search and paths tab
def get_terms(UI, searchterm, filename):
    # the user entered a single search term
    if len(searchterm) > 0:
        searchterms = [searchterm]
        filename    = ""
    else:
        searchterms = []

        try:
            fd = codecs.open(filename, "rb", encoding="UTF-8")
        except:
            UI.msgBox("Unable to open given terms file. Cannot Proceed")
            return None

        for term in fd.readlines():

            # carefully remove newlines from terms...
            if term[-1] == '\n':
                term = term[:-1]

            if term[-1] == '\r':
                term = term[:-1]

            searchterms.append(term)                

    return (searchterms, filename)

# returns the difference of the lists
def diff_lists(orig_results, new_results):
    # get the differences between the two
    orig_only = my_diff(orig_results, new_results)
    new_only  = my_diff(new_results, orig_results)

    # the middle view
    orig_results = my_diff(orig_results, orig_only)

    return (orig_only, new_only, orig_results)

def my_diff(one, two):
    ret = []
    for o in one:
        if not o in two: 
            ret.append(o)

    return ret

# returns a list of the legenth of data_list elements
def get_idxs(data_list):
    idxs = []
    i    = 0

    for d in data_list:
        l = len(d)
        idxs.append(l)
        i = i + 1
        
    return idxs

# returns None on error or the updated search term list
def valid_file_date_params(UI, searchterm, searchfile, startDate, endDate):
    ret = None
    
    # check search terms
    terms = common.get_terms(UI, searchterm, searchfile)

    if terms:
        if not startDate or common.parse_date(startDate):
            if not endDate or common.parse_date(endDate):
                ret = terms[0] # the updated searchterm
            else:
                UI.msgBox("Invalid end date given.")
        else:
           UI.msgBox("Invalid start date given.")
    else:
        UI.msgBox("Invalid search term or search file given.")
    
    return ret


