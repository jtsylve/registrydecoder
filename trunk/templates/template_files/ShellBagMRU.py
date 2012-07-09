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
# Version 0.4

pluginname = "Shell BagMRU"
description = "Contain information on folder settings, " \
  "view options for recently viewed folders/files"
hives = ['NTUSER', 'USRCLASS']
documentation = ""

def run_me():

  import struct
  import string
  import uuid
  from datetime import datetime

  date_format = '%Y/%m/%d %H:%M:%S UTC'

  panel_types = {
    'bb64f8a7-bee7-4e1a-ab8d-7d8273f7fdb6':'Action Center',
    '7a979262-40ce-46ff-aeee-7884ac3b6136':'Add Hardware',
    'd20ea4e1-3957-11d2-a40b-0c5020524153':'Administrative Tools',
    '9c60de1e-e5fc-40f4-a487-460851a8d915':'AutoPlay',
    'b98a2bea-7d42-4558-8bd1-832f41bac6fd':'Backup and Restore Center',
    '0142e4d0-fb7a-11dc-ba4a-000ffe7ab428':'Biometric Devices',
    'd9ef8727-cac2-4e60-809e-86f80a666c91':'BitLocker Drive Encryption',
    'b2c761c6-29bc-4f19-9251-e6195265baf1':'Color Management',
    '1206f5f1-0569-412c-8fec-3204630dfb70':'Credential Manager',
    'e2e7934b-dce5-43c4-9576-7fe4f75e7480':'Date and Time',
    '00c6d95f-329c-409a-81d7-c46c66ea7f33':'Default Location',
    '17cd9488-1228-4b2f-88ce-4298e93e0966':'Default Programs',
    '37efd44d-ef8d-41b1-940d-96973a50e9e0':'Desktop Gadgets',
    '74246bfc-4c96-11d0-abef-0020af6b0b7a':'Device Manager',
    'a8a91a66-3a7d-4424-8d24-04e180695c7a':'Devices and Printers',
    'c555438b-3c23-4769-a71f-b6d3d9b6053a':'Display',
    'd555645e-d4f8-4c29-a827-d93c859c4f2a':'Ease of Access Center',
    '6dfd7c5c-2451-11d3-a299-00c04f8ef6af':'Folder Options',
    '93412589-74d4-4e4e-ad0e-e0cb621440fd':'Fonts',
    '259ef4b1-e6c9-4176-b574-481532c9bce8':'Game Controllers',
    '15eae92e-f17a-4431-9f28-805e482dafd4':'Get Programs',
    'cb1b7f8c-c50a-4176-b604-9e24dee8d4d1':'Getting Started',
    '67ca7650-96e6-4fdd-bb43-a8e774f73a57':'HomeGroup',
    '87d66a43-7b11-4a28-9811-c86ee395acf7':'Indexing Options',
    'a0275511-0e86-4eca-97c2-ecd8f1221d08':'Infrared',
    'a3dd4f92-658a-410f-84fd-6fbbbef2fffe':'Internet Options',
    'a304259d-52b8-4526-8b1a-a1d6cecc8243':'iSCSI Initiator',
    '725be8f7-668e-4c7b-8f90-46bdb0936430':'Keyboard',
    'e9950154-c418-419e-a90a-20c5287ae24b':'Location and Other Sensors',
    '6c8eec18-8d75-41b2-a177-8831d59d2d50':'Mouse',
    '8e908fc9-becc-40f6-915b-f4ca0e70d03d':'Network and Sharing Center',
    '05d7b0f4-2121-4eff-bf6b-ed3f69b894d9':'Notification Area Icons',
    'd24f75aa-4f2b-4d07-a3c4-469b3d9030c4':'Offline Files',
    '96ae8d84-a250-4520-95a5-a47a7e3c548b':'Parental Controls',
    'f82df8f7-8b9f-442e-a48c-818ea735ff9b':'Pen and Input Devices',
    '5224f545-a443-4859-ba23-7b5a95bdc8ef':'People Near Me',
    '78f3955e-3b90-4184-bd14-5397c15f1efc':'Performance Information and Tools',
    'ed834ed6-4b5a-4bfe-8f11-a626dcb6a921':'Personalization',
    '40419485-c444-4567-851a-2dd7bfa1684d':'Phone and Modem',
    '025a5937-a6be-4686-a844-36fe4bec8b6d':'Power Options',
    '2227a280-3aea-1069-a2de-08002b30309d':'Printers',
    'fcfeecae-ee1b-4849-ae50-685dcf7717ec':'Problem Reports and Solutions',
    '7b81be6a-ce2b-4676-a29e-eb907a5126c5':'Programs and Features',
    '9fe63afd-59cf-4419-9775-abcc3849f861':'Recovery',
    '62d8ed13-c9d0-4ce8-a914-47dd628fb1b0':'Regional and Language Options',
    '241d7c96-f8bf-4f85-b01f-e2b043341a4b':'RemoteApp and Desktop Connections',
    '00f2886f-cd64-4fc9-8ec5-30ef6cdbe8c3':'Scanners and Cameras',
    'f2ddfc82-8f12-4cdd-b7dc-d4fe1425aa4d':'Sound',
    '58e3c745-d971-4081-9034-86e34b30836a':'Speech Recognition Options',
    '9c73f5e5-7ae7-4e32-a8e8-8d23b85255bf':'Sync Center',
    'bb06c0e4-d293-4f75-8a90-cb05b6477eee':'System ',
    '80f3f1d5-feca-45f3-bc32-752c152e456e':'Tablet PC Settings',
    '0df44eaa-ff21-4412-828e-260a8728e7f1':'Taskbar and Start Menu',
    'd17d1d6d-cc3f-4815-8fe3-607e7d5d10b3':'Text to Speech',
    'c58c4893-3be0-4b45-abb5-a63e4b8c8651':'Troubleshooting',
    '60632754-c523-4b62-b45c-4172da012619':'User Accounts',
    'be122a0e-4503-11da-8bde-f66bad1e3f3a':'Windows Anytime Upgrade',
    '78cb147a-98ea-4aa6-b0df-c8681f69341c':'Windows CardSpace',
    'd8559eb9-20c0-410e-beda-7ed416aecc2a':'Windows Defender',
    '4026492f-2f69-46b8-b9bf-5654fc07e423':'Windows Firewall',
    '3e7efb4c-faf1-453d-89eb-56026875ef90':'Windows Marketplace',
    '5ea4f148-308c-46d7-98a9-49041b1dd468':'Windows Mobility Center',
    '087da31b-0dd3-4537-8e23-64a18591f88b':'Windows Security Center',
    'e95a4861-d57a-4be1-ad0f-35267e261739':'Windows SideShow',
    '36eef7db-88ad-4e81-ad49-0e313f0c35f8':'Windows Update'}

  folder_types = {
    '724ef170-a42d-4fef-9f26-b60e846fba4f':'Administrative Tools',
    'd0384e7d-bac3-4797-8f14-cba229b392b5':'Common Administrative Tools',
    'de974d24-d9c6-4d3e-bf91-f4455120b917':'Common Files',
    'c1bae2d0-10df-4334-bedd-7aa20b227a9d':'Common OEM Links',
    '5399e694-6ce5-4d6c-8fce-1d8870fdcba0':'Control Panel',
    '1ac14e77-02e7-4e5d-b744-2eb1ae5198b7':'CSIDL_SYSTEM',
    'b4bfcc3a-db2c-424c-b029-7fe99a87c641':'Desktop',
    '7b0db17d-9cd2-4a93-9733-46cc89022e7c':'Documents Library',
    'fdd39ad0-238f-46af-adb4-6c85480369c7':'Documents',
    '374de290-123f-4565-9164-39c4925e467b':'Downloads',
    'de61d971-5ebc-4f02-a3a9-6c82895e5c04':'Get Programs',
    'a305ce99-f527-492b-8b1a-7e76fa98d6e4':'Installed Updates',
    '871c5380-42a0-1069-a2ea-08002b30309d':'Internet Explorer (Homepage)',
    '031e4825-7b94-4dc3-b131-e946b44c8dd5':'Libraries',
    '4bd8d571-6d19-48d3-be97-422220080e43':'Music',
    '20d04fe0-3aea-1069-a2d8-08002b30309d':'My Computer',
    '450d8fba-ad25-11d0-98a8-0800361b1103':'My Documents',
    'ed228fdf-9ea8-4870-83b1-96b02cfe0d52':'My Games',
    '208d2c60-3aea-1069-a2d7-08002b30309d':'My Network Places',
    'f02c1a0d-be21-4350-88b0-7367fc96ef3c':'Network', 
    '33e28130-4e1e-4676-835a-98395c3bc3bb':'Pictures',
    'a990ae9f-a03b-4e80-94bc-9912d7504104':'Pictures',
    '7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e':'Program Files (x86)',
    '905e63b6-c1bf-494e-b29c-65b732d3d21a':'Program Files',
    'df7266ac-9274-4867-8d55-3bd661de872d':'Programs and Features',
    '3214fab5-9757-4298-bb61-92a9deaa44ff':'Public Music',
    'b6ebfb86-6907-413c-9af7-4fc2abf07cc5':'Public Pictures',
    '2400183a-6185-49fb-a2d8-4a392a602ba3':'Public Videos',
    '491e922f-5643-4af4-a7eb-4e7a138d8174':'Public',
    'dfdf76a2-c82a-4d63-906a-5644ac457385':'Public',
    '645ff040-5081-101b-9f08-00aa002f954e':'Recycle Bin',
    'd65231b0-b2f1-4857-a4ce-a8e7c6ea7d27':'System32 (x86)',
    '9e52ab10-f80d-49df-acb8-4330f5687855':'Temporary Burn Folder',
    'f3ce0f7c-4901-4acc-8648-d5d44b04ef8f':'Users Files',
    '59031a47-3f72-44a7-89c5-5595fe6b30ee':'Users',
    'f38bf404-1d43-42f2-9305-67de0b28fc23':'Windows'}

  class MRUEntry:
    def __init__(self, name="", path="", mru_type="", mru_value="", 
                 accessed_date="", created_date="", modified_date="",
                 zip_opened_date="", parent_value=""):
      self.name = name
      self.path = path
      self.mru_type = mru_type
      self.mru_value = mru_value
      self.accessed_date = accessed_date
      self.created_date = created_date
      self.modified_date = modified_date
      self.zip_opened_date = zip_opened_date  # zip file subfolders only
      self.parent_value = parent_value

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
    def determine_mru_type(cls, value):
      # Determines the type of BagMRU Entry for subsequent processing
      mru_type_dict = {'\x31':'Folder',
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

      if value in mru_type_dict:
        return mru_type_dict[value]
      else: # for data types that we don't know about yet and as placeholder
        return 'Unrecognized Type'

    @classmethod
    def parse_bagmru_data(cls, name, path, data):
      # Parses the MRU data and returns a MRUEntry Class 
      # object containing the parsed contents

      size, = struct.unpack('H', data[0:2])
      mru_type_val = data[2]     
      mru_type = cls.determine_mru_type(mru_type_val)

      if data[6] == '\x05':
        mru_type = 'URI / Folder'
      # System Folders such as My Computer, My Network Places, etc.
      if mru_type == 'System Folder':
        rv = cls.parse_system_mru(mru_type, name, path, data)
      # Drive Letters that are part of MRU path (i.e. C:\, D:\, etc.)
      elif mru_type == 'Volume':
        rv = cls.parse_volume_mru(mru_type, name, path, data)
      # Windows Networking components MRU values
      elif mru_type == 'Microsoft Windows Network' \
           or mru_type == 'Windows Domain' \
           or mru_type == 'Computer Name' \
           or mru_type == 'Remote Share' \
           or mru_type == 'Entire Network':
        if mru_type == 'Remote Share' and data[3] != '\x01':
          rv = cls.parse_unknown_type(mru_type, name, path, data, size)
        else:
          rv = cls.parse_win_network(mru_type, name, path, data)
      elif mru_type == 'Folder' or mru_type == 'Zip File':
        rv = cls.parse_folder(mru_type, name, path, data)
      elif mru_type == 'Device':
        rv = cls.parse_device_mru(mru_type, name, path, data)
      # This handles BagMRU values with varied structure
      elif mru_type == 'Variable':
        rv = cls.parse_variable_mru(mru_type, name, path, data)                              
      elif mru_type == 'Control Panel':
        rv = cls.parse_control_panel(mru_type, name, path, data)
      elif mru_type == 'URI':
        rv = cls.parse_uri(mru_type, name, path, data)
      elif mru_type == 'URI / Folder':
        rv = cls.parse_uri_folder(mru_type, name, path, data)
      # For Unknown values - placeholders for the time being to 
      # keep path alignment for subsequent MRU entries
      else:                                                                                 
        rv = cls.parse_unknown_type(mru_type, name, path, data, size)
      return rv
    
    @classmethod
    def parse_system_mru(cls, mru_type, name, path, data):
      # Process MRU Entries classified as SYSTEM FOLDER in mru_type
      sys_type_dict = {'\x50':'My Computer', 
                       '\x58':'My Network Places',
                       '\x48':'My Documents',
                       '\x42':'Libraries',
                       '\x60':'Recycle Bin', 
                       '\x78':'Recycle Bin', 
                       '\x44':'Users', 
                       '\x70':'Control Panel',
                       '\x00':'Explorer', 
                       '\x80':'My Games', 
                       '\x68':'Explorer'}
      sys_value = data[3]
      if sys_value in sys_type_dict:
        sys_type = sys_type_dict[sys_value]          
      else:# For folders we cannot identify the type of
        sys_type = 'Unrecognized System Folder'                     

      mru_data = cls(name=name, 
                     path=path, 
                     mru_type=sys_type, 
                     mru_value=sys_type + ":")
      return mru_data

    @classmethod
    def parse_volume_mru(cls, mru_type, name, path, data):
      # Parses MRU Entries classified as Drive in mru_type
      # Drive Letter value always at offset 3 in registry entry
      drive_letter = data[3:5]
      mru_data = cls(name=name,
                     path=path,
                     mru_type=mru_type,
                     mru_value=drive_letter + "\\")
      return mru_data

    @classmethod
    def parse_device_mru(cls, mru_type, name, path, data):
      # Parses Device MRU Entries. Some entries contain device entries 
      # as commonly seen in setupapi.log file
      # Username and device name lengths
      user_string_length, = struct.unpack('I', data[30:34])                         
      device_string_length, = struct.unpack('I', data[34:38])
      # String length does not include utf-16 null terminated values 
      user_string_length *= 2                                                                                               
      device_string_length *= 2
      end_device_string = user_string_length + device_string_length
      try:
        user_string_value = cls.get_string(data[40:
          40+user_string_length].decode('utf-16'))
      except:
        user = ''
      try:
        device_string_value = cls.get_string(data[40+user_string_length:
          40+end_device_string].decode('utf-16'))
      except:
        device = ''
      mru_data = cls(name=name,
                     path=path,
                     mru_type=mru_type,
                     mru_value=user_string_value+":"+device_string_value+"\\")
      return mru_data
    
    @classmethod
    def parse_win_network(cls, mru_type, name, path, data):
      # Parses Windows Network MRU entries
      # String Value containing path/description of network component
      net_name = cls.get_string(data[5:])
      if mru_type == 'Computer Name' or mru_type == 'Remote Share':
        net_name = net_name[1:]
      mru_data = cls(name=name,
                     path=path,
                     mru_type=mru_type,
                     mru_value=net_name + "\\")
      return mru_data
    
    @classmethod
    def parse_control_panel(cls, mru_type, name, path, data):
      m = MRUEntry()
      control_panel_uuid = uuid.UUID(bytes_le=data[14:30])
      if str(control_panel_uuid) in panel_types:
        panel_type = panel_types[str(control_panel_uuid)]
      else:
        panel_type = '{' + str(control_panel_uuid) + '}'
      mru_data = cls(name=name,
                     path=path,
                     mru_type=mru_type,
                     mru_value=panel_type)
      return mru_data
    
    @classmethod
    def parse_uri(cls, mru_type, name, path, data):
      uri_string = ''
      if data[3] == '\x80':
        uri_string = cls.get_string(data[6:].decode('utf-16'))
      else:
        uri_string = cls.get_string(data[46:])
        try:
          data = data.split('\x04\x00\x00\x00\x00\x00\x00\x00')
          proto = cls.get_string(data[-1])
        except:
          proto = ''
        uri_string = proto + '://' + uri_string
      uri_string += '/'
      mru_data = cls(name=name,
                     path=path,
                     mru_type=mru_type,
                     mru_value=uri_string)
      return mru_data

    @classmethod
    def parse_variable_mru(cls, mru_type, name, path, data):
      # This handles MRU values with readable contents but structure is varied
      mru_value = ''
      if data[4] == '\x1a':
        mru_type = 'Folder'
        fl_uuid = uuid.UUID(bytes_le=data[14:30])
        if str(fl_uuid) in folder_types:
          mru_value = folder_types[str(fl_uuid)]
        else:
          mru_value = '{' + str(fl_uuid) + '}'
      else:                                                                               
        try:
          # Sections of other varied MRU types appear to have 
          # data sections split by 1SPS
          test_1sps_list = data.split('1SPS')
          mru_type = 'Folder'
          mru_len, = struct.unpack('I', test_1sps_list[1][29:33])
          # String data starts 33 bytes from start of data section.
          # String length does not include utf-16 null values for each 
          # character thus double length
          mru_value = cls.get_string(test__1sps_list[1][33:
                                                33+mru_len*2].decode('utf-16'))    
        except:
          pass
      mru_data = cls(name=name, 
                     path=path, 
                     mru_type=mru_type,
                     mru_value=mru_value + "\\")
      return mru_data
    
    @classmethod
    def parse_uri_folder(cls, mru_type, name, path, data):
      try:
        ascii_item = cls.get_string(data[38:])
        unicode_item = cls.get_string(data[46:].decode('utf-16'))

        if unicode_item == '':
          unicode_item = ascii_item

        unicode_item += '/'  
        mru_data = cls(name=name,
                       path=path,
                       mru_type=mru_type,
                       mru_value=item)
      except: # exception - just keep entry as placeholder
        mru_data = cls(name=name,
                       path=path,
                       mru_type=mru_type)
      return mru_data

    @classmethod
    def parse_unknown_type(cls, mru_type, name, path, data, size):
      # Placeholder for Unknown MRU types - return empty MRUEntry class Object
      # Attempting to parse entries that may be zip file subfolder entries
      mru_data = cls(name=name,
                     path=path,
                     mru_type=mru_type)       
      if size > 68:
        try:
          # Zip subfolder names appear to always start at offset 68, 
          # containing a variable length unicode string
          zip_folder_path = cls.get_string(data[68:].decode('utf-16'))                                                    
          if zip_folder_path != '':                                                                                     
            try:
              # Zip subfolder entries contain a unicode string value at 
              # offset 24 of when folder was accessed/opened
              date_opened = cls.get_string(data[24:].decode('utf-16'))                                                
              if len(date_opened) < 15:
                date_opened = '' #Invalid date entry
              else:
                date_opened += ' Local Time' # date in local system time
            except:
              date_opened = ''
            mru_data = cls(name=name,
                           path=path,
                           mru_type="Zip Subfolder",
                           mru_value=zip_folder_path,
                           zip_opened_date=date_opened)
        except:
          pass                                      
      return mru_data

    @classmethod
    def parse_folder(cls, mru_type, name, path, data):
      # Parses Folder, Zip File and Symbolic Link Folder MRU Entries
      # These containing the most data including shortname, longname, 
      # and date attributes
      
      # Modification Date (original file date/time)
      modified_date, = struct.unpack('H', data[8:10])
      modified_time, = struct.unpack('H', data[10:12])
      if modified_date > 1 and modified_time > 0:
        try:
          mod = cls.convert_DOS_datetime_to_UTC(modified_date, modified_time)
          modified = mod.strftime(date_format)
        except:
          modified = ''
      else:
        modified = '' 

      m_type = struct.unpack('B', data[12])# Always seems to be \x10 for folders
      data_block1 = struct.unpack('B', data[13])# unknown value
      short_name = cls.get_string(data[14:])
      # The ptr variable will keep track of place in entry from here
      ptr = len(short_name) + 14 

      # Maintaining Alignment - Below handles files with odd (literally) 
      # length short names. If short name length is odd, increment pointer 
      # by 9, if even increment by 10
      if ptr % 2 != 0:
        data_block2 = data[ptr:ptr+9] # unknown data block
        ptr += 9
      else:
        data_block2 = data[ptr:ptr+10] # unknown data block
        ptr +=10

      # Creation Date (original file date/time) 
      creation_date, = struct.unpack('H', data[ptr:ptr+2])
      creation_time, = struct.unpack('H', data[ptr+2:ptr+4])
      if creation_date > 1 and creation_time > 0:
        try:
          crt = cls.convert_DOS_datetime_to_UTC(creation_date, creation_time)
          created = crt.strftime(date_format)
        except:
          created = '' 
      else:
        created = '' 

      # Last Accessed Date (original file date/time) 
      a_date, = struct.unpack('H', data[ptr+4:ptr+6])
      a_time, = struct.unpack('H', data[ptr+6:ptr+8])
      if a_date > 1 and a_time > 0:
        try:
          acc = cls.convert_DOS_datetime_to_UTC(creation_date, creation_time)
          accessed = acc.strftime(date_format)
        except:
          accessed = ''
      else:
        accessed = ''
      
      # Check value to determine how far to move pointer. This value appears to 
      # be based on OS version
      check_val, = struct.unpack('B', data[ptr+8])

      if check_val == 20:
        # Unicode name string is null terminated, add 1 to keep valid position
        end_string = data.find('\x00\x00', ptr+12)+1
        # Sometimes Unicode decode fails, or in rare cases the 
        # longname doesn't  contain valid characters
        try:
          long_name = cls.get_string(data[ptr+12:end_string].decode('utf-16'))
        except:
          long_name = short_name
      elif check_val == 42:
        end_string = data.find('\x00\x00', ptr+34)+1
        try:
          long_name = cls.get_string(data[ptr+34:end_string].decode('utf-16'))
        except:
          long_name = short_name
      else: # check_val == 38
        end_string = data.find('\x00\x00', ptr+30)+1
        try:
          long_name = cls.get_string(data[ptr+30:end_string].decode('utf-16'))
        except:
          long_name = short_name
      if not long_name:
        long_name = short_name
      mru_data = cls(name=name,
                     path=path,
                     mru_type=mru_type,
                     mru_value=long_name + "\\",
                     modified_date=modified,
                     created_date=created,
                     accessed_date=accessed)
      return mru_data

    @classmethod
    def parse_mrulistex(cls, data):
      # Determines list order of Stream entries
      mru_order = []      
      ptr = 0
      # Each MRUListEx entry is 4 bytes (uint) and 
      # \xFF\xFF\xFF\xFF signifies the end of the entries data
      while data[ptr:ptr+4] != '\xFF\xFF\xFF\xFF':
        mru, = struct.unpack('I', data[ptr:ptr+4])
        mru_order.append(mru)
        ptr += 4
      return mru_order 

    @classmethod
    def list_all_mru_keys(cls, key):
      key_list = [] # return value
      # Collecting BagMRU Root Values        
      values = reg_get_values(key)
      key_path = full_path_node_to_root(key).lstrip(root_key())
      for val in values:
        full_path = key_path + '\\' # Building path for sub-entries
        name = reg_get_value_name(val)
        # This will be implemented in a later version
        # TODO(kevin): add mru parsing to output order
        if name == 'MRUListEx':
          continue
          #data = reg_get_raw_value_data(val)
          #mru_order = parse_mrulistex(data)
        elif name != 'NodeSlot' and name != 'NodeSlots':  
          full_path += name
          path_and_vals = full_path, val
          key_list.append(path_and_vals)

      # Collecting BagMRU Subkey Values        
      for path in key_list:
        try:
          skey = reg_get_required_key(path[0])
        except:
          continue
        values = reg_get_values(skey)
        for val in values:
          full_path = path[0] + '\\' # Building Path for sub-entries
          name = reg_get_value_name(val)
          # This will be implemented in a later version
          # TODO(kevin): add mru parsing to output order          
          if name == 'MRUListEx':
            continue
            #data = reg_get_raw_value_data(val)
            #mru_order = parse_mrulistex(data)
          elif name != 'NodeSlot' and name != 'NodeSlots':  
            full_path += name # Building path for sub-entries
            path_and_vals = full_path, val 
            key_list.append(path_and_vals)
            
      key_list.sort()
      return key_list

    @classmethod
    def process_bagmru_entries(cls, keys):
      # Sets up processing of BagMRU entries
      # Concatenates parent/child entries for full MRU path
      vals = []    # return value
      for key in keys: 
        name = reg_get_value_name(key[1])
        path = key[0]
        data = reg_get_raw_value_data(key[1])
        mru = cls.parse_bagmru_data(name, path, data) 
        mru.parent_value = cls.get_parent(mru.path) 
        
        # This works effectively because MRU entries are parsed in order
        # so the parent entry is always parsed before child
        for val in vals:
          if mru.parent_value == val.path:                 
            mru.mru_value = val.mru_value + mru.mru_value      
        vals.append(mru)
      return vals

    @classmethod
    def get_parent(cls, path):
      # Gets registry path of parent registry key
      split_path = path.rpartition('\\')
      parent = split_path[0]
      return parent

  def print_report(parsed_mrus):
    # Prints Report for Plugin
    if len(parsed_mrus) == 0:
      reg_report(('No Shell BagMRU Entries Identified in Registry File'))
    else:
      reg_set_report_header(("Registry Path",
                             "MRU Value", 
                             "MRU Type", 
                             "Last Modified Date", 
                             "Creation Date", 
                             "Last Accessed Date", 
                             "Zip Subfolder Accessed Date (Local Time)"))
      for mru in parsed_mrus:
        reg_report((mru.path, 
                    mru.mru_value, 
                    mru.mru_type, 
                    mru.modified_date, 
                    mru.created_date, 
                    mru.accessed_date, 
                    mru.zip_opened_date))

  parsed_mru_values = []
  
  mru_instance = MRUEntry()
  # Check to see if path exists. This key usually doesn't in Win7/Vista 
  # NTUSER registry hives
  if path_exists(root_key() + 
                 "\Software\Microsoft\Windows\ShellNoRoam\BagMRU"):
    regkey = \
      reg_get_required_key("\Software\Microsoft\Windows\ShellNoRoam\BagMRU")
    MRU_keys = mru_instance.list_all_mru_keys(regkey)
    parsed_vals = mru_instance.process_bagmru_entries(MRU_keys)
    parsed_mru_values.extend(parsed_vals)
    
  if path_exists(root_key() + "\Software\Microsoft\Windows\Shell\BagMRU"):
    regkey = reg_get_required_key("\Software\Microsoft\Windows\Shell\BagMRU") 
    MRU_keys = mru_instance.list_all_mru_keys(regkey)
    parsed_vals = mru_instance.process_bagmru_entries(MRU_keys)           
    parsed_mru_values.extend(parsed_vals)
    
  if path_exists(root_key() + 
                 '\Local Settings\Software\Microsoft\Windows\shell\BagMRU'):

    regkey = \
      reg_get_required_key('\Local Settings\Software\Microsoft'
                           '\Windows\shell\BagMRU')
    MRU_keys = list_all_mru_keys(regkey)
    parsed_vals = process_bagmru_entries(MRU_keys)
    parsed_mru_values.extend(parsed_vals)

  if path_exists(root_key() + 
                 '\Wow6432Node\Local Settings\Software\Microsoft'
                 '\Windows\shell\BagMRU'):

    regkey = \
      reg_get_required_key('\Wow6432Node\Local Settings\Software\Microsoft'
                           '\Windows\shell\BagMRU')
    MRU_keys = list_all_mru_keys(regkey) 
    parsed_vals = process_bagmru_entries(MRU_keys)
    parsed_mru_values.extend(parsed_vals)

  print_report(parsed_mru_values) 


