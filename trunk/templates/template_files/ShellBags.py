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
# Kevin Moore - km@while1forensics.com
# Version 0.3

pluginname = "Shell Bags"
description = "Contains information on icon position"
hives = ['NTUSER', 'USRCLASS'] 
documentation = ""

def run_me():

  import struct
  from datetime import datetime

  date_format = '%Y/%m/%d %H:%M:%S UTC'

  class ShellBags:
    def __init__(self, offset_in_entry=0, full_key_path="", registry_value="",
                 mru_entry_size=0, mru_type="",
                 original_file_size=0, modified_date="", created_date="",
                 accessed_date="", mru_value=""):
      self.offset_in_entry = offset_in_entry
      self.full_key_path = full_key_path
      self.registry_value = registry_value
      self.mru_entry_size = mru_entry_size
      self.mru_type = mru_type
      self.original_file_size = original_file_size
      self.modified_date = modified_date
      self.created_date = created_date
      self.accessed_date = accessed_date
      self.mru_value = mru_value
      
    @classmethod
    def get_string(cls, string_data):
      # Function returns readable shortname and longname string entries
      import string
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
    def parse_bag_data(cls, data, entry_name, keypath):
      # This function parses through bag data entries and process 
      # each bag entry section. Returns a list with Bags class objects 
      # containing parsed data
  
      ptr = 0 # pointer in registry entry
      if entry_name.startswith('ItemPos'):
        data = data[:-4] # 4 empty (00) bytes at end of file
      else:
        data = data[:-3] # 3 empty (00) bytes at end of file
      
      # For ItemOrder files, first 16 bytes contain unknown data 
      # that we won't parse. # For ItemPos files, first 24 bytes 
      # contain unknown data that we won't parse
      if entry_name.startswith('ItemOrder'):
        ptr += 16                          
      else:    # ItemPos
        ptr += 24                          
  
      bag_data = []
      while ptr < len(data):
        size, = struct.unpack('H', data[ptr:ptr+2]) # size of bag entry
        bag = cls.parse_bag_entry(ptr, data[ptr:ptr+size], keypath, entry_name)
        bag_data.append(bag)
        if entry_name.startswith('ItemPos'):
          ptr += size + 8 # ItemPos entry size does not account for 8 bytes
        else:
          ptr += size # ItemOrder accounts for full size of entry
      return bag_data 

    @classmethod
    def parse_bag_entry(cls, offset, segment, reg_key, reg_entry):
      # This function parses all the Shell Bags entries from 
      # ItemPos and ItemOrder files
      bags_list = []  # return value
      # System Shortcuts (i.e. My Computer) all contain 0x1f at offset 2
      if segment[2] == '\x1f': 
        sys_entry = cls.parse_system_bag_entry(segment, 
                                               offset, 
                                               reg_key, 
                                               reg_entry)
        return sys_entry
  
      #All Other Files and Folders
      else:
        dict_file_type = {'\x32':'File',
                          '\x31':'Folder',
                          '\x3a':'File'} 
  
        size, = struct.unpack('H', segment[0:2]) # Size of bag entry
        file_type = segment[2] 
        # size of file/folder - for shortcuts, size of lnk file
        file_size, = struct.unpack('I', segment[4:8])
  
        # Modification Date (original file date/time)
        modified_date, = struct.unpack('H', segment[8:10])
        modified_time, = struct.unpack('H', segment[10:12])
        if modified_date > 1 and modified_time > 0: 
          try:
            mod = cls.convert_DOS_datetime_to_UTC(modified_date, modified_time)
            modified = mod.strftime(date_format)
          except:
            modified = '' # corrupt or invalid date value - set to null string
        else:
          modified = '' # Invalid or corrupt date values
  
        entry_type, = struct.unpack('B', segment[12])
        data_block1 = segment[13] # unknown data block
        short_name = cls.get_string(segment[14:]) # DOS8.3 Name
        
        # ptr will keep track of place in file from here
        ptr = len(short_name) + 14
  
        # Maintaining Alignment - Below handles files with odd (literally) 
        # length short names. If short name length is odd, increment pointer 
        # by 9, if even by 10
        if ptr % 2 != 0:
          data_block2 = segment[ptr:ptr+9] # unknown data block
          ptr += 9
        else:
          data_block2 = segment[ptr:ptr+10] # unknown data block
          ptr +=10
  
        # Creation Date (original file date/time) 
        created_date, = struct.unpack('H', segment[ptr:ptr+2])
        created_time, = struct.unpack('H', segment[ptr+2:ptr+4])
        if created_date > 1 and created_time > 0:
          try:
            crt = cls.convert_DOS_datetime_to_UTC(created_date, created_time)
            created = crt.strftime(date_format)
          except:
            created = '' # corrupt or invalid date value - set to null string
        else:
          created = ''  # Invalid or corrupt date values
  
        # Last Accessed Date (original file date/time) 
        accessed_date, = struct.unpack('H', segment[ptr+4:ptr+6]) 
        accessed_time, = struct.unpack('H', segment[ptr+6:ptr+8])
        if accessed_date > 1 and accessed_time > 0:
          try:
            acc = cls.convert_DOS_datetime_to_UTC(created_date, created_time)
            accessed = acc.strftime(date_format)
          except:
            accessed = '' # corrupt or invalid date value - set to null string
        else:
          accessed = '' # Invalid or corrupt date values
  
        check_value, = struct.unpack('B', segment[ptr+8])
        if check_value == 20:      # XP & 2K3
          # Unicode name string is null terminated, add 1 to keep valid position
          end_string = segment.find('\x00\x00', ptr+12)+1
          try:
            long_name = cls.get_string(segment[ptr+12:
                                                end_string].decode('utf-16'))
          except:
            long_name = short_name
        elif check_value == 42:    # Win7 
          end_string = segment.find('\x00\x00', ptr+34)+1
          try:
            long_name = cls.get_string(segment[ptr+34:
                                                end_string].decode('utf-16'))
          except:
            long_name = short_name
        else: # check_val == 38  # Vista
          end_string = segment.find('\x00\x00', ptr+30)+1
          try:
            long_name = cls.get_string(segment[ptr+30:
                                               end_string].decode('utf-16'))
          except:
            long_name = short_name
  
        if file_type in dict_file_type:
          mru_type = dict_file_type[file_type]
        else:
          mru_type = "Unknown"
          
        shell_bag_instance = cls(offset_in_entry=offset,
                                 mru_entry_size=size,
                                 full_key_path=reg_key,
                                 registry_value=reg_entry,
                                 mru_type=mru_type,
                                 original_file_size=file_size,
                                 modified_date=modified,
                                 created_date=created,
                                 accessed_date=accessed,
                                 mru_value=long_name)
        return shell_bag_instance         
    
    @classmethod
    def parse_system_bag_entry(cls, segment, offset, key, entry):
      # Bag Entry for System Folder -  see dictionary below
      # These entries do not appear to contain date/time values

      dict_sys_type = {'\x50':'My Computer', 
                       '\x60':'Recycle Bin', 
                       '\x78':'Recycle Bin', 
                       '\x58':'My Network Places', 
                       '\x48':'My Documents', 
                       '\x42':'Application File Dialog'}
  
      size, = struct.unpack('H', segment[0:2])
      sys_type = segment[3]
      if sys_type in dict_sys_type:
        shell_bag_type = dict_sys_type[sys_type]
      else:
        shell_bag_type = 'Unrecognized System Type'
      
      shell_bag_instance = cls(offset_in_entry=offset,
                               full_key_path=key,
                               registry_value=entry,
                               mru_type='Shortcut',
                               mru_value=shell_bag_type)
      return shell_bag_instance

    @classmethod
    def get_bag_entries(cls, subkeys, location):
      # This function identifies keys in the ShellNoRoam and Shell 
      # Bags folders. Passes parseable Bags keys to parse_bag_data 
      # for processing.
      bag_values = []
      for key in subkeys:
        key_path = location
        key_name = reg_get_key_name(key)
        key_path += '\%s' % key_name
  
        # Processing Subkeys and Checking Paths
        if key_name == '1':
          try:
            # Desktop ShellBags entries are only under Key value 1    
            new_key_path = key_path + '\Desktop'        
            skey = reg_get_required_key(new_key_path)
            key_path = new_key_path
          except: 
            try:
              key_path += '\shell'
              skey = reg_get_required_key(key_path)
            except: 
              continue
        else:
          try:
            key_path += '\shell'
            skey = reg_get_required_key(key_path)
          except: 
            continue
  
        values = reg_get_values(skey)
        for val in values:
          name = reg_get_value_name(val)
          if name.startswith('ItemOrder') or name.startswith('ItemPos'): 
            shell_bag_entry = cls.parse_bag_data(reg_get_raw_value_data(val), 
                                                 name, 
                                                 key_path)
            bag_values.extend(shell_bag_entry)
  
        try:
          new_subkeys = reg_get_subkeys(skey)
        except:
          continue
  
        if new_subkeys:
          # Processing Subkey Values for valid ShellBags entries
          for sk in new_subkeys:
            name = reg_get_key_name(sk)
            new_key_path = key_path + '\%s' % name
            k = reg_get_required_key(new_key_path)
            values = reg_get_values(k)
            for val in values:
              name = reg_get_value_name(val)
              if name.startswith('ItemOrder') or name.startswith('ItemPos'):
                shell_bag_entry = cls.parse_bag_data(reg_get_raw_value_data(val), 
                                                     name, 
                                                     new_key_path)
                bag_values.extend(shell_bag_entry)
            new_key_path = key_path
      return bag_values

  def print_report(shell_bag_entries):
    # Prints Report for Plugin
    if len(shell_bag_entries) == 0:
      reg_report(('No Shell Bags Entries Identified in Registry File'))
    else:
      reg_set_report_header(("Registry Path",
                             "Registry Key : Offset", 
                             "MRU Value", 
                             "Shell Bag Type", 
                             "Original File Size", \
                             "Last Modified Date", 
                             "Creation Date", 
                             "Last Accessed Date"))  
      for shell_bag_entry in shell_bag_entries:
          reg_report((shell_bag_entry.full_key_path, 
                      shell_bag_entry.registry_value + ' : ' +
                        str(shell_bag_entry.offset_in_entry), 
                      shell_bag_entry.mru_value,  
                      shell_bag_entry.mru_type,
                      str(shell_bag_entry.original_file_size),
                      shell_bag_entry.modified_date,
                      shell_bag_entry.created_date,
                      shell_bag_entry.accessed_date))

  all_bags = []
  # NTUSER Registry Files   
  if path_exists(root_key() + "\Software\Microsoft\Windows\ShellNoRoam\Bags"):
    regkey = reg_get_required_key("\Software\Microsoft\Windows"
                                  "\ShellNoRoam\Bags")
    subkeys = reg_get_subkeys(regkey)
    bags = ShellBags.get_bag_entries(subkeys, "\Software\Microsoft\Windows"
                           "\ShellNoRoam\Bags")
    all_bags.extend(bags)
  if path_exists(root_key() + "\Software\Microsoft\Windows\Shell\Bags"):

    regkey = reg_get_required_key("\Software\Microsoft\Windows\Shell\Bags")
    subkeys = reg_get_subkeys(regkey)
    bags = ShellBags.get_bag_entries(subkeys, "\Software\Microsoft\Windows"
                                     "\Shell\Bags")
    all_bags.extend(bags)

  # USRClass Registry Files        
  if path_exists(root_key() + 
                 "\Local Settings\Software\Microsoft\Windows\shell\Bags"):
    regkey = reg_get_required_key("\Local Settings\Software\Microsoft"
                                  "\Windows\shell\Bags")
    subkeys = reg_get_subkeys(regkey)
    bags = ShellBags.get_bag_entries(subkeys, "\Local Settings\Software"
                                     "\Microsoft\Windows\shell\Bags")
    all_bags.extend(bags)
  if path_exists(root_key() + "\Wow6432Node\Local Settings\Software\Microsoft"
                 "\Windows\shell\Bags"):
    regkey = reg_get_required_key("\Wow6432Node\Local Settings\Software"
                                  "\Microsoft\Windows\shell\Bags")
    subkeys = reg_get_subkeys(regkey)
    bags = ShellBags.get_bag_entries(subkeys, "\Wow6432Node\Local Settings"
                                     "\Software\Microsoft\Windows\shell\Bags")
    all_bags.extend(bags)
    
  print_report(all_bags)

