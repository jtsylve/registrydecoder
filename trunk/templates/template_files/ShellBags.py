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
# TODO: UsrClass.DAT files
#
# Kevin Moore - CERT - kevinm@cert.org

pluginname = "Shell Bags"
description = ""
hives = ['NTUSER', 'USRCLASS'] 
documentation = ""

def run_me():
    
    import struct
    from datetime import datetime
    
    date_format = '%Y/%m/%d %H:%M:%S UTC'                             # Change this to the date format you prefer
    
    # BAGS CLASS
    
    class Bags:
        def __init__(self):
            
            self.offset = 0
            self.reg_path = ""
            self.reg_value = ""
            self.size = 0
            self.file_type = ""
            self.entry_type = ""
            self.file_size = 0
            self.modified = ""
            self.created = ""
            self.accessed = ""
            self.short_name = ""
            self.long_name = ""
                                                            
        def get_string(self,string_data):
            
            # Function returns readable shortname and longname string entries
            
            import string
            name = []
            for s in string_data:
                if s in string.printable:
                    name.append(s)
                else: break
            return ''.join(name)
        
        # ENDFUNCTION get_string
        
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
        
        # ENDFUNCTION - convert_DOS_datetime_to_UTC
        
        def set_bag_data(self, offset, size, path, value, file_type, entry_type, file_size, mod_date, create_date, acc_date, short_name, long_name):
            
            self.offset = offset
            self.size = size
            self.reg_path = path
            self.reg_value = value
            self.file_type = file_type
            self.entry_type = entry_type
            self.file_size = file_size
            self.modified = mod_date
            self.created = create_date
            self.accessed = acc_date
            self.short_name = short_name
            self.long_name = long_name
        
        # ENDFUNCTION - set_bag_data
            
    # ENDCLASS - BAGS CLASS        
    
    def parse_bag_data(data, entry_name, keypath):
        
        # This function parses through bag data entries and process each bag entry section
        # Returns a list with Bags class objects containing parsed data
        
        p = 0                                # pointer in registry entry
        if entry_name.startswith('ItemPos'):
            data = data[:-4]                 # 4 empty (00) bytes at end of file
        else:
            data = data[:-3]                 # 3 empty (00) bytes at end of file
        
        if entry_name.startswith('ItemOrder'):
            p += 16                          # For ItemOrder files, first 16 bytes contain unknown data that we won't parse
        else:    # ItemPos
            p += 24                          # For ItemPos files, first 24 bytes contain unknown data that we won't parse
                        
        # Looping through entire registry entry - there can be multiple Shell Bags reference in a single entry
        
        bag_data = []
        
        while p < len(data):

            size, = struct.unpack('H', data[p:p+2])                                  # size of bag entry
            bag = parse_bag_entry(p, data[p:p+size], keypath, entry_name)            # parse single bag entry return Bags class object
            bag_data.append(bag)
            if entry_name.startswith('ItemPos'):
                p += size + 8                                                        # ItemPos entry size does not account for 8 bytes for some reason
            else:
                p += size                                                            # ItemOrder accounts for full size of entry
    
        return bag_data                                                              # returns a list of bags class objects containing parsed data from registry entry
    
    # ENDFUNCTION - parse_bag_data
    
    def parse_bag_entry(offset, segment, reg_key, reg_entry):
            
        # Nuts and Bolts of the Plugin.
        # This function parses all the Shell Bags entries from ItemPos and ItemOrder files
        
        bags_list = []  # return value
        
        # System Shortcuts
        if segment[2] == '\x1f':                                         # System Folder (i.e. My Computer) all contain 0x1f at offset 2
            
            sys_entry = parse_system_bag_entry(segment, offset, reg_key, reg_entry)
            return sys_entry
        
        #All Other Files and Folders
        else:
            bags = Bags()
            
            dict_file_type = {50:'FILE',49:'FOLDER',58:'FILE'}           # Known File Type Dictionary (decimal)
            
            size, = struct.unpack('H', segment[0:2])                     # Size of bag entry
            file_type, = struct.unpack('B', segment[2])                  # Bag entry type - see file type dictionary above - questionable difference between SHORTCUT and FILE
            file_size, = struct.unpack('I', segment[4:8])                # size of file/folder - for shortcuts, size of lnk file
            
            # Modification Date (original file date/time)
            m_date, = struct.unpack('H', segment[8:10])                  # DOSDATE Entry
            m_time, = struct.unpack('H', segment[10:12])                 # DOSTIME Entry
            if m_date > 1 and m_time > 0:                                # Handles invalid or corrupt date values
                mod = bags.convert_DOS_datetime_to_UTC(m_date, m_time)   # Convert Date/Time to readable output
                modified = mod.strftime(date_format)
            else:
                modified = ''                                            # Invalid or corrupt date values
                
            entry_type, = struct.unpack('B', segment[12])                # Bag entry type - appears to be either FILE (0x20) or FOLDER (0x16)
            
            data_block1 = segment[13]                                    # unknown data block
            
            short_name = bags.get_string(segment[14:])                   # DOS8.3 Name
            
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
                crt = bags.convert_DOS_datetime_to_UTC(c_date, c_time)   # Convert Date/Time to readable input
                created = crt.strftime(date_format)
            else:
                created = ''                                             # Invalid or corrupt date values
                
            # Last Accessed Date (original file date/time) 
            a_date, = struct.unpack('H', segment[ptr+4:ptr+6])           # DOSDATE Entry 
            a_time, = struct.unpack('H', segment[ptr+6:ptr+8])           # DOSDATE Entry
            if a_date > 1 and a_time > 0:                                # Handles invalid or corrupt date values
                acc = bags.convert_DOS_datetime_to_UTC(c_date, c_time)   # Convert Date/Time to readable input
                accessed = acc.strftime(date_format)
            else:
                accessed = ''                                            # Invalid or corrupt date values
            
            check_val, = struct.unpack('B', segment[ptr+8])              # Check value to determine how far to move pointer
            
            if check_val == 20:      # XP & 2K3
                end_string = segment.find('\x00\x00', ptr+12)+1          # Unicode name string is null terminated, add 1 to keep valid position
                try:
                    long_name = bags.get_string(segment[ptr+12:end_string].decode('utf-16'))  # Longname listed in Unicode (UTF-16)
                except:
                    long_name = short_name
                    
            elif check_val == 42:    # Win7 
                end_string = segment.find('\x00\x00', ptr+34)+1          # Unicode name string is null terminated, add 1 to keep valid position
                try:
                    long_name = bags.get_string(segment[ptr+34:end_string].decode('utf-16'))  # Longname listed in Unicode (UTF-16)
                except:
                    long_name = short_name
                    
            else: # check_val == 38  # Vista
                end_string = segment.find('\x00\x00', ptr+30)+1          # Unicode name string is null terminated, add 1 to keep valid position
                try:
                    long_name = bags.get_string(segment[ptr+30:end_string].decode('utf-16')) # Longname listed in Unicode (UTF-16)
                except:
                    long_name = short_name
                    
            # Sets Bags class object of parsed data for report later on    
            bags.set_bag_data(offset, size, reg_key, reg_entry, dict_file_type[file_type], entry_type, file_size, modified, created, accessed, short_name, long_name)

            return bags
        
    # ENDFUNCTION - parse_bag_entry          
                
    def parse_system_bag_entry(segment, offset, key, entry):
            
            # Bag Entry for System Folder -  see dictionary below
            # These entries do not appear to contain date/time values
            
            bags = Bags()
            
            dict_sys_type = {80:'My Computer', 96:'Recycle Bin', 120:'Recycle Bin', 88:'My Network Places', 
                             72:'My Documents', 66:'Application File Dialog'}
            
            size, = struct.unpack('H', segment[0:2])
            
            sys_type, = struct.unpack('B', segment[3])                 # System Shortcut type as reference in dictionary above (decimal)
            
            if sys_type in dict_sys_type:
                bags.set_bag_data(offset, size, key, entry, 'SHORTCUT','','','','','','',dict_sys_type[sys_type])
            else:
                bags.set_bag_data(offset, size, key, entry, 'SHORTCUT','','','','','','','Unrecognized System Type')
            
            return bags
        
    # ENDFUNCTION parse_system_bag_entry
        
    def get_bag_entries(subkeys, location):
        
        # This function identifies keys in the ShellNoRoam and Shell Bags folders
        # Passes parseable Bags keys to parse_bag_data for processing
        # Returns a List of Bags class objects containing all parsed Shell Bags values
        
        bag_values = []
        
        for key in subkeys:
            
            key_path = location
                
            key_name = reg_get_key_name(key)
            key_path += '\%s' % key_name
            
            # Processing Subkeys and Checking Paths
            if key_name == '1':
                try:
                    new_key_path = key_path + '\Desktop'                   # Desktop ShellBags entries are only under Key value 1            
                    skey = reg_get_required_key(new_key_path)
                    key_path = new_key_path
                except: 
                    try:
                        key_path += '\shell'                               # If there isn't a Desktop folder, check to see if there is a shell folder like
                        skey = reg_get_required_key(key_path)              # other ShellBags entries
                    except: continue                                       # Some do not contain 'shell' folders and only contain 'ComDlg' folders which do not contain content we parse
            else:
                try:
                    key_path += '\shell'                                   # Standard path for ShellBags entries is under a folder name 'Shell'
                    skey = reg_get_required_key(key_path)                  # although there may be subkey values
                except: continue                                           # Some do not contain 'shell' folders and only contain 'ComDlg' folders which do not contain content we parse
                
            values = reg_get_values(skey)
            
            for val in values:
                name = reg_get_value_name(val)
                if name.startswith('ItemOrder') or name.startswith('ItemPos'):                               # ItemOrder and ItemPos contain file information, other entries do not appear
                    item = parse_bag_data(reg_get_raw_value_data(val), name, key_path)                   #        to be of interest. At this time they are not parsed
                    bag_values.extend(item)
                        
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
                        if name.startswith('ItemOrder') or name.startswith('ItemPos'):                               # ItemOrder and ItemPos contain file information, other entries do not appear
                            item = parse_bag_data(reg_get_raw_value_data(val), name, new_key_path)                   #        to be of interest. At this time they are not parsed
                            bag_values.extend(item)
                            
                    new_key_path = key_path
            
        return bag_values
    
    # ENDFUNCTION - get_bag_entries
    
    def print_report(parsed):
        
        # Prints Report for Plugin
        
        if len(parsed) == 0:
            reg_report(('No Shell Bags Entries Identified in Registry File'))
        
        else:
        
            reg_set_report_header(("Registry Path","Registry Key : Offset", "Long Name", "Short Name", "Bag Type", "File Size", \
                    "Last Modified Date", "Creation Date", "Last Accessed Date"))  
    
            for p in parsed:
                
                if p.file_type == 'SHORTCUT':                     # System Shortcut Values
                    reg_report((p.reg_path, p.reg_value + ' : ' + str(p.offset), p.long_name, p.short_name, p.file_type))
                    
                else:                                             # All Other Values
                    reg_report((p.reg_path, p.reg_value + ' : ' + str(p.offset), p.long_name, p.short_name, p.file_type, str(p.file_size), \
                            p.modified, p.created, p.accessed))

    # ENDFUNCTION print_report
      
    #***************************#
    # Main Processing Functions
     
    all_bags = []
    
    # NTUSER Registry Files
    if hive == 'NTUSER':
        
        # ShellNoRoam    
        if path_exists(root_key() + "\Software\Microsoft\Windows\ShellNoRoam\Bags"):
            
            regkey = reg_get_required_key("\Software\Microsoft\Windows\ShellNoRoam\Bags")
            subkeys = reg_get_subkeys(regkey)
            bags = get_bag_entries(subkeys, "\Software\Microsoft\Windows\ShellNoRoam\Bags")
            all_bags.extend(bags)
        
        # Shell
        if path_exists(root_key() + "\Software\Microsoft\Windows\Shell\Bags"):
            
            regkey = reg_get_required_key("\Software\Microsoft\Windows\Shell\Bags")
            subkeys = reg_get_subkeys(regkey)
            bags = get_bag_entries(subkeys, "\Software\Microsoft\Windows\Shell\Bags")
            all_bags.extend(bags)
    
    # END NTUSER Processing
    
    # USRClass Registry Files        
    else: # hive == 'USRCLASS'
        
        # Non Wow64
        if path_exists(root_key() + "\Local Settings\Software\Microsoft\Windows\shell\Bags"):                    # Check path exists
        
            regkey = reg_get_required_key("\Local Settings\Software\Microsoft\Windows\shell\Bags")
            subkeys = reg_get_subkeys(regkey)
            bags = get_bag_entries(subkeys, "\Local Settings\Software\Microsoft\Windows\shell\Bags")             # Processes Subkeys for ShellBags Entries
            all_bags.extend(bags)
        
        # Wow64 Entries - 64-bit systems
        if path_exists(root_key() + "\Wow6432Node\Local Settings\Software\Microsoft\Windows\shell\Bags"):        # Check path exists
            regkey = reg_get_required_key("\Wow6432Node\Local Settings\Software\Microsoft\Windows\shell\Bags")
            subkeys = reg_get_subkeys(regkey)
            bags = get_bag_entries(subkeys, "\Wow6432Node\Local Settings\Software\Microsoft\Windows\shell\Bags") # Processes Subkeys for ShellBags Entries
            all_bags.extend(bags)
            
    # END USRClass processing

    print_report(all_bags)
    
    report((""))


