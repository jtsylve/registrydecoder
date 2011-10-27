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
# Kevin Moore - CERT - kevinm@cert.org 

pluginname = "User Assist"
description = ""
hive = "NTUSER"    
documentation = ""

ver_7_2008_ids = ("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}")

def run_me():
    
    import struct
    from datetime import datetime
    
    date_format = '%Y/%m/%d %H:%M:%S UTC'                          # Change this to the format you prefer
    
    def convert_win_to_unix(windate):
        
        # Converts 8-byte Windows Date/Time stamps to Unix Date/Time stamps so python can deal with it better
        
        no_nano = windate/10000000 # 10000000 - 100 nanosecond intervals in windows timestamp, remove them to get to seconds since windows epoch
        unix = no_nano - 11644473600 # number of seconds between 1/1/1601 and 1/1/1970
        return unix
    
    # ENDFUNCTION - convert_win_to_unix
    
    reg_set_report_header(("UserAssist Value","SessionID","Run Count","Last Ran Date", "Key ID"))

    regkey = reg_get_required_key("\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    subkeys = reg_get_subkeys(regkey)
    
    for key in subkeys:
        
        key_name = reg_get_key_name(key)
        
        key_path = "\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        key_path += "\%s\count" % key_name
        
        skey = reg_get_required_key(key_path)
        values = reg_get_values(skey)
        
        for val in values:
            
            name = rot13(reg_get_value_name(val))
            data = reg_get_raw_value_data(val)                      # Grabs raw hex values associated with registry entry
            
            if key_name in ver_7_2008_ids:
                
                if data >= 68:
                    
                    runcount, = struct.unpack("I", data[4:8])                 # Run Count - 4 byte int
                    dateval, = struct.unpack("Q", data[60:68])                # Windows Date - Quad - 8 btye date/time value
                    
                    if dateval > 0:                                         # Make sure it is a valid date
                        
                            dt = convert_win_to_unix(dateval)                 # converts from Windows to Unix so python can deal with it
                            
                            if dt >= 0:                                 # Makes sure it is a valid date
                                reg_report((name, '', str(runcount), datetime.fromtimestamp(int(dt)).strftime(date_format), key_name))
                            else:                                       # If not valid, just print name and runcount
                                reg_report((name, '', str(runcount), '', key_name))
                    else:                                 
                            reg_report((name, '', str(runcount), '', key_name))

                else:                                                          # Else just print the name
                    reg_report((name, '', '', key_name))
                        
            # Vista, XP & 2K3
            elif len(data) == 16:                                 # All XP & 2003 UserAssist values are 16 btyes long
                    
                session, runcount, dateval = struct.unpack("IIQ", data)            # SessionID , RunCount , Last Ran Date              
                runcount -= 5                               # In 2K3 and XP RunCount starts counting at 5 
                
                if dateval > 0:
                    
                    dt = convert_win_to_unix(dateval)                 # converts from Windows to Unix so python can deal with it
                    
                    if dt >= 0:                                 # Like above, checks for valid date/time value       
                        reg_report((name, str(session), str(runcount), datetime.fromtimestamp(int(dt)).strftime(date_format), key_name)) # ROT13 name, Session ID, RunCount, Last Run Date              
                    else:                                       
                        reg_report((name, str(session), str(runcount), key_name)) # UserAssist Values with invalid last run date
                
                else:
                    reg_report((name, '', '', '', key_name)) # UserAssist Values with blank last run date
                    
            elif len(data) < 16:
                reg_report((name, '', '', '', key_name))
                


