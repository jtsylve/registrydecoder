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
# Recent Docs
# ver 1.0 
# 07/18/2011
#
# Updated by Kevin Moore - km@while1forensics.com
# 7/12/12

pluginname = "Recent Docs Ordered"
description = "Displays files and folders recently accessed by this user " \
  "and ordered by their associated MRUListEx value"
hive = "NTUSER"    

def run_me():

  import struct

  def chunks(l, n):
    list = []
    for i in range(0, len(l), n):
      list.append(str(l[i:i+n]))
    return list

  def determine_mru_order(reg_value_data):
    mru_order = []      
    ptr = 0
    # Each MRUListEx entry is 4 bytes (uint) and \xFF\xFF\xFF\xFF 
    # signifies the end of the entries data
    while reg_value_data[ptr:ptr+4] != '\xFF\xFF\xFF\xFF':                                   
      mru, = struct.unpack('I', reg_value_data[ptr:ptr+4])
      mru_order.append(mru)
      ptr += 4
    return mru_order

  def get_recent_doc_values(key):
    entry_values = {}
    recent_doc_entries = reg_get_values(key)
    order = None
    for value in recent_doc_entries:
      name = reg_get_value_name(value)
      # MRUListEx provides an ordered list of when RecentDocs 
      # entries were accessed
      if name.lower() in ['viewstream']:
        continue # Research needs to be conducted to determine if any data of
                 # value can be gained from this key
      if name.lower() in ['mrulistex']:
        value_data = reg_get_raw_value_data(value)
        order = determine_mru_order(value_data)
        split_mrulist = chunks(order, 20)
        # Prints a list of the MRUListEx ordered list for reference)
        reg_report(('MRUListEx Order: ', '\n'.join(split_mrulist)))
      else:
        value_data = reg_get_value_data(value)
        entry_values[name] = value_data
    if order is None:
      for k, v in entry_values.iteritems():
        reg_report((v, str(k)))
    else:
      for item in order:
        try:
          item = str(item)
          reg_report((entry_values[item],str(item)))
        except:
          reg_report(('***ERROR: Unidentified MRUList Entry', str(item)))
    
  key_path = "\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
  key = reg_get_required_key(key_path)    
  report((key_path, reg_get_lastwrite(key))) 
  get_recent_doc_values(key) # Get Root Entries under RecentDocs folder
  subkeys = reg_get_subkeys(key) # Get subfolder values

  for key in subkeys:
    report((key_path + "\\" + reg_get_key_name(key), reg_get_lastwrite(key)))
    get_recent_doc_values(key)

