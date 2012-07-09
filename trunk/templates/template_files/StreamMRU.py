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
# StreamMRU
# Version 0.2
#
# Kevin Moore - km@while1forensics.com
# 

pluginname = "StreamMRU"
description = ""
hives = "NTUSER"
documentation = ""

def run_me():

  import struct
  import string
  from datetime import datetime

  date_format = '%Y/%m/%d %H:%M:%S UTC' 

  class Stream:
    def __init__(self, key_name="", offset_in_entry=0, original_file_size=0,
                 full_key_path="", concatenated_path="", mru_type="",
                 mru_value="", accessed_date="",
                 created_date="", modified_date=""):
      self.key_name = key_name
      self.offset_in_entry = offset_in_entry
      self.size_of_value = original_file_size
      self.full_key_path = full_key_path
      self.concatenated_path = concatenated_path
      self.mru_type = mru_type
      self.mru_value = mru_value
      self.accessed_date = accessed_date
      self.created_date = created_date
      self.modified_date = modified_date

    @classmethod
    def get_string(cls, string_data):
      # Function returns readable shortname and longname string entries
      name = []
      for s in string_data:
        if s in string.printable:
          name.append(s)
        else: break
      return ''.join(name)

    @classmethod
    def convert_DOS_datetime_to_UTC(cls, date, time):
      # As Referenced in libforensics time.py:
      #       http://code.google.com/p/libforensics/
      # DOS DATETIME Reference:
      #       http://msdn.microsoft.com/en-us/library/windows/desktop/ms724274(v=VS.85).aspx
      seconds = (time & 0x1F) * 2
      minutes = (time & 0x7E0) >> 5
      hours = (time & 0xF800) >> 11
      day = date & 0x1F 
      month = (date & 0x1E0) >> 5
      year = ((date & 0xFE00) >> 9) + 1980 
      return datetime(year, month, day, hours, minutes, seconds)

    @classmethod
    def parse_mrulistex(cls, mrulistex_registry_value):
      # Determines list order of Stream entries
      mru_order = []      
      index = 0
      # Each MRUListEx entry is 4 bytes (uint) and \xFF\xFF\xFF\xFF 
      # signifies the end of the entries data
      while mrulistex_registry_value[index:index+4] != '\xFF\xFF\xFF\xFF':
        mru, = struct.unpack('I', mrulistex_registry_value[index:index+4])
        mru_order.append(mru)
        index += 4
      return mru_order 

    @classmethod
    def determine_mru_type(cls, value):
      # Determines the type of BagMRU Entry for subsequent processing
      mru_types = {'\x31':'Folder',
                   '\xc3':'Remote Share',
                   '\x41':'Windows Domain',
                   '\x42':'Computer Name',
                   '\x46':'Microsoft Windows Network', 
                   '\x47':'Entire Network',
                   '\x1f':'System Folder',
                   '\x2f':'Volume',
                   '\x32':'Zip File', 
                   '\x48':'My Documents', 
                   '\x00':'Variable',
                   '\xb1':'File Entry', 
                   '\x71':'Control Panel', 
                   '\x61':'URI'}
      if value in mru_types:
        return mru_types[value]
      else: # for data types that we don't know about yet and as placeholder
        return 'Unrecognized Type'             

    @classmethod
    def parse_stream_data(cls, key_name, key_path, data):
      # Parses through stream entry for individual values
      stream_data = []
      index = 0
      prev_val = ''
      while index < len(data):
        size, = struct.unpack('H', data[index:index+2]) # size of bag entry
        if size == 0: # invalid entry - no data
          break
        stream, concatenate_value = \
          cls.parse_stream_entry(offset_in_entry=index, 
                                 data_segment=data[index:index+size], 
                                 registry_key_path=key_path, 
                                 registry_entry=key_name, 
                                 previous_value=prev_val)
        stream_data.append(stream)
        # Append parsed stream value to rebuild path from 
        # multiple entries in stream data
        prev_val += concatenate_value                                                 
        index += size # Jump to next entry in stream value
      return stream_data # returns all values from stream entry

    @classmethod
    def parse_stream_entry(cls, offset_in_entry=0, data_segment=None, 
                           registry_key_path=None, registry_entry=None, 
                           previous_value=None):
      # Determines type of stream entry for processing 
      mru_type_value = data_segment[2] # determines stream entry type
      mru_type = cls.determine_mru_type(mru_type_value)
  
      # System Entries
      if mru_type == 'System Folder':                                         
        stream_mru_instance = cls.parse_system_entry(data_segment=data_segment, 
                                   offset_in_entry=offset_in_entry, 
                                   registry_key_path=registry_key_path, 
                                   registry_entry=registry_entry)
      # Drive letter entries
      elif mru_type == 'Volume':
        stream_mru_instance = cls.parse_drive_entry(data_segment=data_segment, 
                                  offset_in_entry=offset_in_entry, 
                                  registry_key_path=registry_key_path, 
                                  registry_entry=registry_entry,
                                  previous_value=previous_value)
      #All Other Files and Folders
      else:
        stream_mru_instance = cls.parse_folder_entry(data_segment=data_segment, 
                                       offset_in_entry=offset_in_entry, 
                                       registry_key_path=registry_key_path, 
                                       registry_entry=registry_entry,
                                       previous_value=previous_value)
      return stream_mru_instance

    @classmethod
    def parse_folder_entry(cls, data_segment=None, offset_in_entry=0, 
                           registry_key_path=None, registry_entry=None, 
                           previous_value=None):
      stream_mru_entry_types = {'\x32':'File',
                                '\x31':'Folder',
                                '\x3a':'File'}
      size, = struct.unpack('H', data_segment[0:2]) # Size of bag entry
      mru_type = data_segment[2] 
      # size of file/folder - for shortcuts, size of lnk file
      file_size, = struct.unpack('I', data_segment[4:8])
  
      # Modification Date (original file date/time)
      modified_date, = struct.unpack('H', data_segment[8:10])
      modified_time, = struct.unpack('H', data_segment[10:12])
      if modified_date > 1 and modified_time > 0: 
        try:
          mod = cls.convert_DOS_datetime_to_UTC(modified_date, modified_time)
          modified = mod.strftime(date_format)
        except:
          modified = '' # corrupt or invalid date value
      else:
        modified = '' # Invalid or corrupt date values
  
      entry_type, = struct.unpack('B', data_segment[12]) 
      data_block1 = data_segment[13] # unknown data block
      short_name = cls.get_string(data_segment[14:]) # DOS8.3 Name
      
      # ptr will keep track of place in file from here
      ptr = len(short_name) + 14 
      # Maintaining Alignment - Below handles files with odd (literally) 
      # length short names. If short name length is odd, increment pointer 
      # by 9, if even by 10
      if ptr % 2 != 0:
        data_block2 = data_segment[ptr:ptr+9] # unknown data block
        ptr += 9
      else:
        data_block2 = data_segment[ptr:ptr+10] # unknown data block
        ptr +=10
  
      # Creation Date (original file date/time) 
      creation_date, = struct.unpack('H', data_segment[ptr:ptr+2]) 
      creation_time, = struct.unpack('H', data_segment[ptr+2:ptr+4]) 
      if creation_date > 1 and creation_time > 0: 
        try:
          crt = cls.convert_DOS_datetime_to_UTC(creation_date, creation_time) 
          created = crt.strftime(date_format)
        except:
          created = '' # corrupt or invalid date value
      else:
        created = '' # Invalid or corrupt date values
  
      # Last Accessed Date (original file date/time) 
      accessed_date, = struct.unpack('H', data_segment[ptr+4:ptr+6])
      accessed_time, = struct.unpack('H', data_segment[ptr+6:ptr+8]) 
      if accessed_date > 1 and accessed_time > 0:
        try:
          acc = cls.convert_DOS_datetime_to_UTC(creation_date, creation_time) 
          accessed = acc.strftime(date_format)
        except:
          accessed = '' # corrupt or invalid date value
      else:
        accessed = '' # Invalid or corrupt date values
  
      # Check value to determine how far to move pointer. Varies based on
      # operating system
      check_value, = struct.unpack('B', data_segment[ptr+8])
  
      if check_value == 20: # XP & 2K3
        # Unicode name string is null terminated, add 1 to keep valid position
        end_string = data_segment.find('\x00\x00', ptr+12)+1 
        try:
          long_name = cls.get_string(data_segment[ptr+12:
                                                  end_string].decode('utf-16')) 
        except:
          long_name = short_name
  
      elif check_value == 42: # Win7 
        end_string = data_segment.find('\x00\x00', ptr+34)+1
        try:
          long_name = cls.get_string(data_segment[ptr+34:
                                                  end_string].decode('utf-16'))
        except:
          long_name = short_name
  
      else: # check_val == 38  # Vista
        end_string = data_segment.find('\x00\x00', ptr+30)+1 
        try:
          long_name = cls.get_string(data_segment[ptr+30:
                                                  end_string].decode('utf-16'))
        except:
          long_name = short_name
   
      if mru_type in stream_mru_entry_types:
        mru_type_string = stream_mru_entry_types[mru_type]
      else:
        mru_type_string = "Unknown"
      stream = cls(offset_in_entry=offset_in_entry, 
                   original_file_size=file_size, 
                   key_name=registry_entry, 
                   full_key_path=registry_key_path, 
                   mru_type=mru_type_string,  
                   mru_value=long_name, 
                   concatenated_path=previous_value + long_name + '\\', 
                   modified_date=modified, 
                   created_date=created, 
                   accessed_date=accessed)
  
      return stream, long_name + '\\' 
    
    @classmethod
    def parse_drive_entry(cls, data_segment=None, offset_in_entry=0,
                          registry_key_path=None, registry_entry=None, 
                          previous_value=""):
      # Parses MRU Entries classified as Drive in mru_type
      drive_letter = data_segment[3:5]
      stream = cls(offset_in_entry=offset_in_entry, 
                   key_name=registry_entry, 
                   full_key_path=registry_key_path, 
                   mru_type='Drive', 
                   mru_value=drive_letter, 
                   concatenated_path=previous_value + drive_letter + '\\')
      return stream, drive_letter + '\\'

    @classmethod
    def parse_system_entry(cls, data_segment=None, offset_in_entry=0,
                          registry_key_path=None, registry_entry=None):
  
      # Entry for System Folder -  see dictionary below
      # These entries do not contain date/time values
  
      system_types = {'\x50':'My Computer', 
                      '\x60':'Recycle Bin', 
                      '\x78':'Recycle Bin', 
                      '\x58':'My Network Places', 
                      '\x48':'My Documents', 
                      '\x42':'Application File Dialog'}
  
      size, = struct.unpack('H', data_segment[0:2]) # Size of MRU entry
      system_type_value = data_segment[3]
  
      if system_type_value in system_types:
        system_entry_type = system_types[system_type_value]
        stream = cls(offset_in_entry=offset_in_entry, 
                     key_name=registry_entry,
                     full_key_path=registry_key_path, 
                     mru_type='System Entry',
                     mru_value=system_entry_type,
                     concatenated_path=system_entry_type + ':')
      else:
        system_entry_type = 'Unrecognized System Type:'
        stream = cls(offset_in_entry=offset_in_entry, 
                     key_name=registry_entry,
                     full_key_path=registry_key_path, 
                     mru_type='System Entry',
                     mru_value=system_entry_type,
                     concatenated_path=system_entry_type + ':')
  
      return stream, system_entry_type +':'

  def process_stream_mru_keys(key, values):
    vals = []
    entry_values = {}
    for v in values: 
      registry_value_name = reg_get_value_name(v)
      registry_value_data = reg_get_raw_value_data(v)

      if registry_value_name == 'MRUListEx': # Identifying order of MRU values
        mru_order = Stream.parse_mrulistex(registry_value_data)
      else:
        stream = Stream.parse_stream_data(registry_value_name, 
                                          key_path, 
                                          registry_value_data) 
        entry_values[int(registry_value_name)] = stream

    for i in mru_order: # organizing stream values based on MRUListEx order
      vals.extend(entry_values[i])                              

    return vals

  def print_report(parsed_mrus):
    if len(parsed_mrus) == 0:
      reg_report(('No StreamMRU Entries Identified in Registry File'))
    else:
      reg_set_report_header(("Registry Path",
                             "Key Offset", 
                             "MRU Type", 
                             "Value", 
                             "Concatenated Path",
                             "Last Modified Date", 
                             "Creation Date", 
                             "Last Accessed Date"))
      for stream_mru in parsed_mrus:
        reg_report((stream_mru.full_key_path + '\\' + stream_mru.key_name, 
                    str(stream_mru.offset_in_entry), 
                    stream_mru.mru_type, 
                    stream_mru.mru_value, 
                    stream_mru.concatenated_path, 
                    stream_mru.modified_date, 
                    stream_mru.created_date, 
                    stream_mru.accessed_date))

  parsed_mru_values = []
  key_path = "\Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU"
  if path_exists(root_key() + key_path): 
    regkey = reg_get_required_key(key_path)        
    values = reg_get_values(regkey)
    stream_mru_instances = process_stream_mru_keys(key_path, values) 
    print_report(stream_mru_instances) 
  else:
    reg_report(('No StreamMRU Entries Identified in Registry File'))


