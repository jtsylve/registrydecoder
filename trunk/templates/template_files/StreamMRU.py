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
# Version 0.1
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
    
    date_format = '%Y/%m/%d %H:%M:%S UTC'                     # Change this to the Date/Time format you prefer
    
    class Stream:
        def __init__(self):
            self.name = ""
            self.offset = 0
            self.size = 0
            self.name = ""
            self.path = ""
            self.build_path = ""
            self.mru_type = ""
            self.shortname = ""
            self.longname = ""
            self.accessed = ""
            self.created = ""
            self.modified = ""
            
        def set_stream_data(self, offset, size, name, path, mru_type, shortname, longname, build_path, a_date, c_date, m_date):
            self.offset = offset
            self.size = size
            self.name = name
            self.path = path
            self.mru_type = mru_type
            self.shortname = shortname
            self.longname = longname
            self.build_path = build_path
            self.accessed = a_date
            self.created = c_date
            self.modified = m_date
            return self
        
        def get_string(self,string_data):
            
            # Function returns readable shortname and longname string entries
            
            name = []
            for s in string_data:
                if s in string.printable:
                    name.append(s)
                else: break
            return ''.join(name)
        
        def convert_DOS_datetime_to_UTC(self, date, time):
            
            # As Referenced in libforensics time.py:
            #       http://code.google.com/p/libforensics/
            # DOS DATETIME Reference:
            #       http://msdn.microsoft.com/en-us/library/windows/desktop/ms724274(v=VS.85).aspx
            
            secs = (time & 0x1F) * 2
            mins = (time & 0x7E0) >> 5
            hours = (time & 0xF800) >> 11
            day = date & 0x1F 
            month = (date & 0x1E0) >> 5
            year = ((date & 0xFE00) >> 9) + 1980 
            
            return datetime(year, month, day, hours, mins, secs)
        
    def parse_mrulistex(data):
        
        # Determines list order of Stream entries
        
        mru_order = []      
        ptr = 0
        
        while data[ptr:ptr+4] != '\xFF\xFF\xFF\xFF':            # Each MRUListEx entry is 4 bytes (uint) and \xFF\xFF\xFF\xFF signifies the end of the entries data
            
            mru, = struct.unpack('I', data[ptr:ptr+4])          # Iterate through the file and gather a list of integer values
            mru_order.append(mru)
            ptr += 4
                    
        return mru_order 
    
    # END FUNCTION - parse_mrulistex
    
    def check_value(value):
        
        # Determines the type of BagMRU Entry for subsequent processing
        
        mru_type_dict = {'\x31':'Folder','\xc3':'Remote Share','\x41':'Windows Domain','\x42':'Computer Name',
                         '\x46':'Microsoft Windows Network', '\x47':'Entire Network','\x1f':'System Folder',
                         '\x2f':'Volume','\x32':'Zip File', '\x48':'My Documents', '\x00':'Variable',
                         '\xb1':'File Entry', '\x71':'Control Panel', '\x61':'URI'}
        
        if value in mru_type_dict:
            return mru_type_dict[value]            # Determines MRU type from dictionary above
        
        else:
            return 'Unrecognized Type'             # for data types that we don't know about yet and as placeholder
    
    # ENDFUNCTION check_value
    
    def parse_stream_data(key_name, key_path, data):
    
        # Parses through stream entry for individual values
        
        stream_data = []
        p = 0
        prev_val = ''
        
        while p < len(data):                                                      # cycles through stream entry to parse contents

            size, = struct.unpack('H', data[p:p+2])                               # size of bag entry
            
            if size == 0:                                                         # invalid entry - no data
                break
            
            stream, new_val = parse_stream_entry(p, data[p:p+size], key_path, key_name, prev_val)  # parse single stream entry return class object
            stream_data.append(stream)
            
            prev_val += new_val                                                  # Append parsed stream value to rebuild path from multiple entries in stream data
            p += size                                                            # Jump to next entry in stream value
    
        return stream_data                                                       # returns all values from stream entry
    
    # END FUNCTION - parse_stream_data
    
    def parse_stream_entry(offset, segment, reg_key, reg_entry, prev):
            
        # Determines type of stream entry for processing 
        
        mru_type_val = segment[2]                                               # determines stream entry type
        
        mru_type = check_value(mru_type_val)
        
        # System Entries
        if mru_type == 'System Folder':                                         
            
            entry = parse_system_entry(segment, offset, reg_key, reg_entry)
        
        # Drive letter entries
        elif mru_type == 'Volume':
            
            entry = parse_drive_entry(segment, offset, reg_key, reg_entry, prev)
        
        #All Other Files and Folders
        else:
            
            entry = parse_folder_entry(segment, offset, reg_key, reg_entry, prev)
            
        return entry
    
    # END FUNCTION - parse_stream_entry
        
    def parse_folder_entry(segment, offset, reg_key, reg_entry, prev):
        
        stream = Stream()
        
        dict_file_type = {'\x32':'FILE','\x31':'FOLDER','\x3a':'FILE'}           # Known File Type Dictionary
        
        size, = struct.unpack('H', segment[0:2])                     # Size of bag entry
        file_type = segment[2]                                       # Bag entry type - see file type dictionary above - questionable difference between SHORTCUT and FILE
        file_size, = struct.unpack('I', segment[4:8])                # size of file/folder - for shortcuts, size of lnk file
        
        # Modification Date (original file date/time)
        m_date, = struct.unpack('H', segment[8:10])                  # DOSDATE Entry
        m_time, = struct.unpack('H', segment[10:12])                 # DOSTIME Entry
        if m_date > 1 and m_time > 0:                                # Handles invalid or corrupt date values
            try:
                mod = stream.convert_DOS_datetime_to_UTC(m_date, m_time)   # Convert Date/Time to readable output
                modified = mod.strftime(date_format)
            except:
                modified = ''                                        # corrupt or invalid date value - set to null string
        else:
            modified = ''                                            # Invalid or corrupt date values
            
        entry_type, = struct.unpack('B', segment[12])                # Bag entry type - appears to be either FILE (0x20) or FOLDER (0x16)
        
        data_block1 = segment[13]                                    # unknown data block
        
        short_name = stream.get_string(segment[14:])                 # DOS8.3 Name
        
        ptr = len(short_name) + 14                                   # ptr will keep track of place in file from here
        
        # Maintaining Alignment - Below handles files with odd (literally) length short names
        # If short name length is odd, increment pointer by 9, if even by 10
        if ptr % 2 != 0:
            data_block2 = segment[ptr:ptr+9]                         # unknown data block
            ptr += 9
        else:
            data_block2 = segment[ptr:ptr+10]                        # unknown data block
            ptr +=10
        
        # Creation Date (original file date/time) 
        c_date, = struct.unpack('H', segment[ptr:ptr+2])             # DOSDATE Entry
        c_time, = struct.unpack('H', segment[ptr+2:ptr+4])           # DOSDATE Entry
        if c_date > 1 and c_time > 0:                                # Handles invalid or corrupt date values
            try:
                crt = stream.convert_DOS_datetime_to_UTC(c_date, c_time)   # Convert Date/Time to readable input
                created = crt.strftime(date_format)
            except:
                created = ''                                         # corrupt or invalid date value - set to null string
        else:
            created = ''                                             # Invalid or corrupt date values
            
        # Last Accessed Date (original file date/time) 
        a_date, = struct.unpack('H', segment[ptr+4:ptr+6])           # DOSDATE Entry 
        a_time, = struct.unpack('H', segment[ptr+6:ptr+8])           # DOSDATE Entry
        if a_date > 1 and a_time > 0:                                # Handles invalid or corrupt date values
            try:
                acc = stream.convert_DOS_datetime_to_UTC(c_date, c_time)   # Convert Date/Time to readable input
                accessed = acc.strftime(date_format)
            except:
                accessed = ''                                        # corrupt or invalid date value - set to null string
        else:
            accessed = ''                                            # Invalid or corrupt date values
        
        check_val, = struct.unpack('B', segment[ptr+8])              # Check value to determine how far to move pointer
        
        if check_val == 20:      # XP & 2K3
            end_string = segment.find('\x00\x00', ptr+12)+1          # Unicode name string is null terminated, add 1 to keep valid position
            try:
                long_name = stream.get_string(segment[ptr+12:end_string].decode('utf-16'))  # Longname listed in Unicode (UTF-16)
            except:
                long_name = short_name
                
        elif check_val == 42:    # Win7 
            end_string = segment.find('\x00\x00', ptr+34)+1          # Unicode name string is null terminated, add 1 to keep valid position
            try:
                long_name = stream.get_string(segment[ptr+34:end_string].decode('utf-16'))  # Longname listed in Unicode (UTF-16)
            except:
                long_name = short_name
                
        else: # check_val == 38  # Vista
            end_string = segment.find('\x00\x00', ptr+30)+1          # Unicode name string is null terminated, add 1 to keep valid position
            try:
                long_name = stream.get_string(segment[ptr+30:end_string].decode('utf-16')) # Longname listed in Unicode (UTF-16)
            except:
                long_name = short_name
               
        # Sets Stream class object of parsed data for report later on    
        stream.set_stream_data(offset, file_size, reg_entry, reg_key, dict_file_type[file_type], short_name, long_name, prev + long_name + '\\', modified, created, accessed)

        return stream, long_name + '\\'                    # return value includes stream data and individual entry value for path rebuilding
     
    # ENDFUNCTION parse_folder
    
    def parse_drive_entry(segment, offset, key, entry, prev):
        
        # Parses MRU Entries classified as Drive in mru_type
        
        stream = Stream()
        
        drv_let = segment[3:5]                            # Drive Letter value always at offset 3 in registry entry
        
        stream = stream.set_stream_data(offset, 0, entry, key, 'Drive', '', drv_let, prev + drv_let + '\\','','','')
        
        return stream, drv_let + '\\'                     # return value includes stream data and drive letter for path rebuilding
    
    # ENDFUNCTION parse_drive_mru
    
    def parse_system_entry(segment, offset, key, entry):
        
        # Entry for System Folder -  see dictionary below
        # These entries do not contain date/time values
        
        stream = Stream()
        
        dict_sys_type = {'\x50':'My Computer', '\x60':'Recycle Bin', '\x78':'Recycle Bin', '\x58':'My Network Places', 
                        '\x48':'My Documents', '\x42':'Application File Dialog'}
        
        size, = struct.unpack('H', segment[0:2])
        
        sys_type_val = segment[3]               # System Shortcut type as reference in dictionary above
        
        if sys_type_val in dict_sys_type:
            sys_type = dict_sys_type[sys_type_val]
            stream.set_stream_data(offset, 0, entry, key, 'System Entry','',sys_type,sys_type + ':','','','')
            
        else:
            sys_type = 'Unrecognized System Type:'
            stream.set_stream_data(offset, 0, entry, key, 'System Entry','',sys_type,sys_type,'','','')
        
        return stream, sys_type +':'                                  # Return value includes full stream data and individual entry value for rebuilding file path
    
    def process_values(key, values):
        
        vals = []                                                     # return value
        entry_values = {}                                             # dictionary of stream values based on numeric reg value 

        for v in values: 
            
            name = reg_get_value_name(v)
            data = reg_get_raw_value_data(v)
            
            if name == 'MRUListEx':
                mru_order = parse_mrulistex(data)               # identifying order of values
                    
            else:
            
                stream = parse_stream_data(name, key_path, data)      # Sends mru data for processing
                entry_values[int(name)] = stream
                
        for i in mru_order:
            vals.extend(entry_values[i])                              # organizing stream values based on MRUListEx order
            
        return vals
    
    # ENDFUNCTION process_values
    
    def print_report(parsed_mrus):
        
        # Prints Report for Plugin
        
        if len(parsed_mrus) == 0:
            reg_report(('No StreamMRU Entries Identified in Registry File'))
        
        else:
            reg_set_report_header(("Registry Path","Key Offset", "MRU Type", "Value", "Rebuilt Path", \
                    "Last Modified Date", "Creation Date", "Last Accessed Date"))
            
            for s in parsed_mrus:
                reg_report((s.path + '\\' + s.name, str(s.offset), s.mru_type, s.longname, s.build_path, s.modified, s.created, s.accessed))
            
    # ENDFUNCTION print_report    
    
    #***************************#
    # Main Processing Functions
    
    parsed_mru_values = []
    key_path = "\Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU"
    
    # ShellNoRoam
    if path_exists(root_key() + key_path):             # Determines if there is a StreamMRU path
               
        regkey = reg_get_required_key(key_path)        
        values = reg_get_values(regkey)
        MRU_keys = process_values(key_path, values)    # Processing Stream values
        print_report(MRU_keys)                         # Printing Report of MRU Values
        
    else:
        reg_report(('No StreamMRU Entries Identified in Registry File')) # StreamMRU path does not exist
        
    


