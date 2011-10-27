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
# Kevin Moore - CERT - kevinm@cert.org

pluginname = "Shell BagMRU"
description = ""
hives = ['NTUSER', 'USRCLASS']
documentation = ""

def run_me():
    
    import struct
    from datetime import datetime
    
    date_format = '%Y/%m/%d %H:%M:%S UTC'                     # Change this to the Date/Time format you prefer
    
    class MRUEntry:
        def __init__(self):
            self.name = ""
            self.path = ""
            self.mru_type = ""
            self.value = ""
            self.accessed = ""
            self.created = ""
            self.modified = ""
            self.parent = ""
            
        def set_mru_data(self, name, path, mru_type, value, a_date, c_date, m_date):
            self.name = name
            self.path = path
            self.mru_type = mru_type
            self.value = value
            self.accessed = a_date
            self.created = c_date
            self.modified = m_date
            return self
        
        def get_string(self,string_data):
            
            # Function returns readable shortname and longname string entries
            
            import string
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
    
    def check_value(value):
        
        # Determines the type of BagMRU Entry for subsequent processing
        
        mru_type_dict = {49:'Folder',195:'Remote Share',65:'Windows Domain',66:'Computer Name',
                         70:'Microsoft Windows Network', 71:'Entire Network',31:'SYSTEM FOLDER',
                         47:'Drive',50:'Zip File', 72:'My Documents', 0:'Variable',
                         177:'Symbolic Link', 113:'System Option'}
        
        if value in mru_type_dict:
            return mru_type_dict[value]            # Determines MRU type from dictionary above
        
        else:
            return 'Unrecognized Type'             # for data types that we don't know about yet and as placeholder
    
    # ENDFUNCTION check_value
        
    def parse_bagmru_data(name, path, data):

        # Parses the MRU data and returns a MRUEntry Class object containing the parsed contents
        
        size, = struct.unpack('H', data[0:2])                                                 # Size of BagMRU entry
        mru_type_val, = struct.unpack('B', data[2])                                           # MRU Type Value       
        mru_type = check_value(mru_type_val)                                                  # Friendly Name of MRU type value - used for further processing based on type
        
        if mru_type == 'SYSTEM FOLDER':                                                       # System Folders such as My Computer, My Network Places, etc.
            ret = parse_system_mru(mru_type, name, path, data)
            
        elif mru_type == 'Drive':                                                             # Drive Letters that are part of MRU path (i.e. C:\, D:\, etc.)
            ret = parse_drive_mru(mru_type, name, path, data)
            
        elif mru_type == 'Microsoft Windows Network' or mru_type == 'Windows Domain' \
             or mru_type == 'Computer Name' or mru_type == 'Remote Share' \
             or mru_type == 'Entire Network':                                                 # Windows Network components
            ret = parse_win_network(mru_type, name, path, data)
            
        elif mru_type == 'Folder' or mru_type == 'Zip File' or mru_type == 'Symbolic Link':   # Zip Files and Folders are processed the same way - these contain date values all others do not
            ret = parse_folder(mru_type, name, path, data)
        
        elif mru_type == 'Device':                                                            # Device MRU types
            ret = parse_device_mru(mru_type, name, path, data)
        
        elif mru_type == 'Variable' or mru_type == 'System Option':                           # For variable mru types and control panel sections
            ret = parse_variable_mru(mru_type, name, path, data)                              # This handles BagMRU values with varied structure
            
        else:                                                                                 # For Unknown values - placeholders for the time being to keep path alignment for subsequent MRU entries
            ret = parse_unknown_type(mru_type, name, path)
            
        return ret
    
    # ENDFUNCTION parse_bagmru_data
    
    def parse_system_mru(mru_type, name, path, data):
        
        # Process MRU Entries classified as SYSTEM FOLDER in mru_type
        
        m = MRUEntry()
        
        sys_type_dict = {80:'My Computer', 88:'My Network Places',72:'My Documents',66:'Application File Dialog',
                     96:'Recycle Bin', 120:'Recycle Bin', 68:'Application File Dialog', 112:'Control Panel'}
        
        sys_value, = struct.unpack('B', data[3])                        # System Value Type is determined by value at offset in raw data of registry entry
        
        if sys_value in sys_type_dict:
            sys_type = sys_type_dict[sys_value]                         # System Folder type determined from dictionary above             
        
        else:
            sys_type = 'Unrecognized System Folder'                     # For folders we cannot identify the type of
    
        mru_data = m.set_mru_data(name, path, sys_type, sys_type + ':', '','','')
        return mru_data
    
    # ENDFUNCTION parse_system_mru
    
    def parse_drive_mru(mru_type, name, path, data):
        
        # Parses MRU Entries classified as Drive in mru_type
        
        m = MRUEntry()
        
        drv_let = data[3:5]                            # Drive Letter value always at offset 3 in registry entry
        
        mru_data = m.set_mru_data(name, path, mru_type, drv_let + '\\', '','','')
        return mru_data
    
    # ENDFUNCTION parse_drive_mru
    
    def parse_device_mru(mru_type, name, path, data):
        
        # Parses Device MRU Entries
        # Some entries contain device entries as commonly seen in setupapi.log file
        # It is unclear when these entries are created
        
        m = MRUEntry()
        
        user_len, = struct.unpack('I', data[30:34])                         # Username referenced with device name
        dev_len, = struct.unpack('I', data[34:38])                          # Device name length
        user_len *= 2                                                       # String length does not include utf-16 null terminated values                                         
        dev_len *= 2                                                        # String length does not include utf-16 null terminated values             
        
        try:
            user = m.get_string(data[40:40+user_len].decode('utf-16'))      # String stored in utf-16
        except:
            user = ''
        try:
            device = m.get_string(data[40+user_len:40+user_len+dev_len].decode('utf-16'))        # String stored in utf-16
        except:
            device = ''
        
        mru_data = m.set_mru_data(name, path, mru_type, user + ':' + device + '\\', '', '', '')
        return mru_data
    
    # ENDFUNCTION parse_device_mru
    
    def parse_win_network(mru_type, name, path, data):
        
        # Parses Windows Network MRU entries
        
        m = MRUEntry()
        
        net_name = m.get_string(data[5:])             # String Value containing path/description of network component
        
        mru_data = m.set_mru_data(name, path, mru_type, net_name + '\\', '','','')
        return mru_data
    
    # ENDFUNCTION parse_win_network
    
    def parse_variable_mru(mru_type, name, path, data):
        
        # This handles MRU values with readable contents but structure is varied
        m = MRUEntry()
        
        app_name = ''
        
        if mru_type == 'System Option':                                                 # Control Panel Selection option
            mru_data = m.set_mru_data(name, path, mru_type,app_name,'','','')                   # Acts as a placeholder
        else:
            app_check, = struct.unpack('B', data[4])
            if app_check == 26:                                                                 # For Application Dialog MRU entries
                mru_type = 'Application'                                                        # Application values have no plaintext, path appears to be
            else:                                                                               #    stored as a hash value. Hash storage value not yet determined
                try:
                    test_list = data.split('1SPS')                                              # Sections of other varied MRU types appear to have data sections split by 1SPS
                    mru_type = 'Application Folder'
                    mru_len, = struct.unpack('I', test_list[1][29:33])                          # Length of name string
                    app_name = m.get_string(test_list[1][33:33+mru_len*2].decode('utf-16'))     # String data starts 33 bytes from start of data section. String length does not include utf-16 null values for each character thus double length
                    app_name += "\\"
                except:
                    pass
                      
        mru_data = m.set_mru_data(name, path, mru_type, app_name,'','','')
        return mru_data
    
    # ENDFUNCTION parse_variable_mru
    
    def parse_unknown_type(mru_type, name, path):
        
        # Placeholder for Unknown MRU types - return empty MRUEntry class Object
        
        m = MRUEntry()
        mru_data = m.set_mru_data(name, path, mru_type,'','','','')
        return mru_data
    
    # ENDFUNCTION parse_unknown_type
    
    def parse_folder(mru_type, name, path, data):
        
        # Parses Folder, Zip File and Symbolic Link Folder MRU Entries
        # These containing the most data including shortname, longname, and date attributes
        
        m = MRUEntry()
        
        # Modification Date (original file date/time)
        m_date, = struct.unpack('H', data[8:10])
        m_time, = struct.unpack('H', data[10:12])
        if m_date > 1 and m_time > 0:                                # Handles invalid or corrupt date values
            mod = m.convert_DOS_datetime_to_UTC(m_date, m_time)      # Convert Date/Time to readable output
            modified = mod.strftime(date_format)
        else:
            modified = ''                                            # Invalid or corrupt date values
        
        m_type = struct.unpack('B', data[12])                        # Always seems to be \x10 for folders
        data_block1 = struct.unpack('B', data[13])                   # unknown
        
        short_name = m.get_string(data[14:])
        
        ptr = len(short_name) + 14                                   # ptr will keep track of place in file from here
                
        # Maintaining Alignment - Below handles files with odd (literally) length short names
        # If short name length is odd, increment pointer by 9, if even by 10
        if ptr % 2 != 0:
            data_block2 = data[ptr:ptr+9]                            # unknown data block
            ptr += 9
        else:
            data_block2 = data[ptr:ptr+10]                           # unknown data block
            ptr +=10
        
        # Creation Date (original file date/time) 
        c_date, = struct.unpack('H', data[ptr:ptr+2])                # DOSDATE Entry
        c_time, = struct.unpack('H', data[ptr+2:ptr+4])              # DOSDATE Entry
        if c_date > 1 and c_time > 0:                                # Handles invalid or corrupt date values
            crt = m.convert_DOS_datetime_to_UTC(c_date, c_time)      # Convert Date/Time to readable input
            created = crt.strftime(date_format)
        else:
            created = ''                                             # Invalid or corrupt date values
        
        # Last Accessed Date (original file date/time) 
        a_date, = struct.unpack('H', data[ptr+4:ptr+6])              # DOSDATE Entry 
        a_time, = struct.unpack('H', data[ptr+6:ptr+8])              # DOSDATE Entry
        if a_date > 1 and a_time > 0:                                # Handles invalid or corrupt date values
            acc = m.convert_DOS_datetime_to_UTC(c_date, c_time)      # Convert Date/Time to readable input
            accessed = acc.strftime(date_format)
        else:
            accessed = ''                                            # Invalid or corrupt date values
        
        check_val, = struct.unpack('B', data[ptr+8])                 # Check value to determine how far to move pointer based on OS version
                
        if check_val == 20:
            end_string = data.find('\x00\x00', ptr+12)+1             # Unicode name string is null terminated, add 1 to keep valid position
            try:                                                     # Sometimes Unicode decode fails, or in rare cases the longname doesn't  contain valid characters
                long_name = m.get_string(data[ptr+12:end_string].decode('utf-16')) # Longname listed in Unicode (UTF-16)
            except:
                long_name = short_name
                
        elif check_val == 42:
            end_string = data.find('\x00\x00', ptr+34)+1             # Unicode name string is null terminated, add 1 to keep valid position
            try:                                                     # Sometimes Unicode decode fails, or in rare cases the longname doesn't  contain valid characters
                long_name = m.get_string(data[ptr+34:end_string].decode('utf-16')) # Longname listed in Unicode (UTF-16)
            except:
                long_name = short_name
                
        else: # check_val == 38
            end_string = data.find('\x00\x00', ptr+30)+1             # Unicode name string is null terminated, add 1 to keep valid position
            try:                                                     # Sometimes Unicode decode fails, or in rare cases the longname doesn't  contain valid characters
                long_name = m.get_string(data[ptr+30:end_string].decode('utf-16')) # Longname listed in Unicode (UTF-16)
            except:
                long_name = short_name
                
        if not long_name:
            long_name = short_name
            
        mru_data = m.set_mru_data(name, path, mru_type, long_name + '\\', modified, created, accessed)
        return mru_data
     
    # ENDFUNCTION parse_folder
    
    def list_all_mru_keys(subkeys, location):
    
        key_list = [] # return value
        
        # This function identifies keys in the ShellNoRoam and Shell Bags folders
        
        key_path = location                                   # sets location we are working from
        
        # Collecting BagMRU Root Values        
        skey = reg_get_required_key(key_path)
        values = reg_get_values(skey)
        
        for val in values:
            
            full_path = key_path + '\\'                       # Building path for sub-entries
            name = reg_get_value_name(val)
            
            if not name.startswith('MRUListEx') and not name.startswith('NodeSlot'):  # These contains MRU order information, but we don't really need that for what we are parsing
                full_path += name                                                     # Building path for sub-entries
                path_and_vals = full_path, val                                        # Appends path and values to our MRU list so we can parse them later on
                key_list.append(path_and_vals)
        
        # ENDFOR
        
        # Collecting BagMRU Subkey Values        
        for path in key_list:
            
            try:
                skey = reg_get_required_key(path[0])              # check to see that we can access key value
            except:pass
            
            values = reg_get_values(skey)
            
            for val in values:
                
                full_path = path[0] + '\\'                        # Building Path for sub-entries
                name = reg_get_value_name(val)
                
                if not name.startswith('MRUListEx') and not name.startswith('NodeSlot'):  # These contains MRU order information, but we don't really need that for what we are parsing
                    full_path += name                                                     # Building path for sub-entries
                    path_and_vals = full_path, val                                        # Appends path and values to our MRU list so we can parse them later on
                    key_list.append(path_and_vals)
         
        # ENDFOR
        
        key_list.sort()
        return key_list                         # returns sorted listed of BagMRU entry values and their contents
         
    # ENDFUNCTION - list_all_mru_keys
    
    def process_bagmru_entries(keys):
        
        # Sets up processing of BagMRU entries
        # Concatenates parent/child entries for full MRU path
        
        vals = []    # return value
        
        for key in keys: 
            
            name = reg_get_value_name(key[1])
            path = key[0]
            data = reg_get_raw_value_data(key[1])
            
            mru = parse_bagmru_data(name, path, data)      # Sends mru data for processing
            mru.parent = get_parent(mru.path)              # Parent entry needed to build path
            
            for val in vals:                               # Checks each MRU for parent and builds path
                if mru.parent == val.path:                 # This works effectively because MRU entries are parsed in order
                    mru.value = val.value + mru.value      #     so parent is always parsed before child
            vals.append(mru)
            
        return vals                                        # Returns full list of parsed/built MRU entries
    
    # ENDFUNCTION process_bagmru_entries
    
    def get_parent(path):
        
        # Gets registry path of parent registry key
        
        split_path = path.rpartition('\\')
        parent = split_path[0]
        return parent
    
    # ENDFUNCTION get_parent
    
    def print_report(parsed_mrus):
        
        # Prints Report for Plugin
        
        if len(parsed_mrus) == 0:
            reg_report(('No Shell BagMRU Entries Identified in Registry File'))
        
        else:
            reg_set_report_header(("Registry Path","MRU Value", "MRU Type", "Last Modified Date", "Creation Date", "Last Accessed Date"))
        
            for mru in parsed_mrus:
                reg_report((mru.path, mru.value, mru.mru_type, mru.modified, mru.created, mru.accessed))
            
    # ENDFUNCTION print_report    
    
    #***************************#
    # Main Processing Functions
    
    parsed_mru_values = []
    
    # NTUSER Registry Files
    #if hive == 'NTUSER':
        
    # ShellNoRoam
    if path_exists(root_key() + "\Software\Microsoft\Windows\ShellNoRoam\BagMRU"):             # Check path exists - usually doesn't in Win7/Vista NTUSER
         
        regkey = reg_get_required_key("\Software\Microsoft\Windows\ShellNoRoam\BagMRU")        # Checks for Registry Key ShellNoRoam\BagMRU
        subkeys = reg_get_subkeys(regkey)                                                      # Gets Subkeys
        MRU_keys = list_all_mru_keys(subkeys, "\Software\Microsoft\Windows\ShellNoRoam\BagMRU")# Gathers List of Usable BagMRU values
        parsed_vals = process_bagmru_entries(MRU_keys)                                         # Processes List of BagMRU Entries for content
        parsed_mru_values.extend(parsed_vals)                                                  # Building List for Report
    
    # Shell
    if path_exists(root_key() + "\Software\Microsoft\Windows\Shell\BagMRU"):                   # Check path exists
          
        regkey = reg_get_required_key("\Software\Microsoft\Windows\Shell\BagMRU")              # Checks for Registry Key Shell\BagMRU
        subkeys = reg_get_subkeys(regkey)                                                      # Gets Subkeys
        MRU_keys = list_all_mru_keys(subkeys, "\Software\Microsoft\Windows\Shell\BagMRU")      # Gathers List of Usable BagMRU values
        parsed_vals = process_bagmru_entries(MRU_keys)                                         # Processes List of BagMRU Entries for content                 
        parsed_mru_values.extend(parsed_vals)                                                  # Building List for Report
    #END if hive == 'NTUSER'
    
    # USRClass registry files        
    #else:    # hive == 'USRCLASS'
        
    # Shell
    if path_exists(root_key() + '\Local Settings\Software\Microsoft\Windows\shell\BagMRU'):               # Check path exists
         
        regkey = reg_get_required_key('\Local Settings\Software\Microsoft\Windows\shell\BagMRU')          # Checks for Registry Key ShellNoRoam\BagMRU
        subkeys = reg_get_subkeys(regkey)                                                                 # Gets Subkeys
        MRU_keys = list_all_mru_keys(subkeys, '\Local Settings\Software\Microsoft\Windows\shell\BagMRU')  # Gathers List of Usable BagMRU values
        parsed_vals = process_bagmru_entries(MRU_keys)                                                    # Processes List of BagMRU Entries for content
        parsed_mru_values.extend(parsed_vals)                                                             # Building List for Report
    
    # Wow6432Node
    if path_exists(root_key() + '\Wow6432Node\Local Settings\Software\Microsoft\Windows\shell\BagMRU'):       # Check path exists - must be 64-bit machine
         
        regkey = reg_get_required_key('\Wow6432Node\Local Settings\Software\Microsoft\Windows\shell\BagMRU')  # Checks for Registry Key ShellNoRoam\BagMRU
        subkeys = reg_get_subkeys(regkey)                                                                     # Gets Subkeys
        MRU_keys = list_all_mru_keys(subkeys, '\Wow6432Node\Local Settings\Software\Microsoft\Windows\shell\BagMRU') # Gathers List of Usable BagMRU values
        parsed_vals = process_bagmru_entries(MRU_keys)                                                        # Processes List of BagMRU Entries for content
        parsed_mru_values.extend(parsed_vals)                                                                 # Building List for Report

# END Else hive == 'USRCLASS'
 
    print_report(parsed_mru_values)                       # Printing Report of MRU Values
    


