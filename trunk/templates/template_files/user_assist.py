# Registry Decoder
# Contact email:  registrydecoder@digitalforensicssolutions.com
#
# Authors:
# Kevin Moore - kevinm@cert.org 
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


pluginname = "User Assist"
description = ""
hives = ["NTUSER", "USRCLASS"]
documentation = ""


ver_7_2008_ids = ("CEBFF5CD-ACE2-4F4F-9178-9926F41749EA", "F4E57C4B-2036-45F0-A9AB-443BCFE33D9F")
    

def run_me():
    import struct
    from datetime import datetime
    
    def convert_win_to_unix(windate):
        no_nano = windate/10000000 # 10000000 - 100 nanosecond intervals in windows timestamp, remove them to get to seconds since windows epoch
        unix = no_nano - 11644473600 # number of seconds between 1/1/1601 and 1/1/1970
        return unix

    date_format = '%m/%d/%Y %H:%M:%S'
    regkey = reg_get_required_key("\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    subkeys = reg_get_subkeys(regkey)
    for key in subkeys:
        key_name = reg_get_key_name(key)
        str_key_name = key_name[1:-1]
        key_path = "\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        key_path += "\%s\count" % key_name
        skey = reg_get_required_key(key_path)
        values = reg_get_values(skey)
        reg_report(("ID:", key_name))
        for val in values:
            name = rot13(reg_get_value_name(val))
            data = reg_get_raw_value_data(val)

            if str_key_name in ver_7_2008_ids:
                y = struct.unpack("I", data[4:8])
                z = struct.unpack("Q", data[60:68])
                if z[0] > 0:
                        dt = convert_win_to_unix(z[0])
                        if dt >= 0:
                            reg_report((name, str(y[0]), datetime.fromtimestamp(int(dt)).strftime(date_format)))
                        else:
                            reg_report((name, str(y[0])))
                else:
                    if y[0] != 0:
                        reg_report((name, str(y[0])))
                    else:
                        reg_report((name))

            else: # pre_7_2008
                if len(data) == 16:
                    x, y, z = struct.unpack("IIQ", data)
                    if z > 0:
                        dt = convert_win_to_unix(z)
                        if dt >= 0:         
                            reg_report((name, str(x), str(y-5), datetime.fromtimestamp(int(dt)).strftime(date_format))) # ROT13 name, Session ID, RunCount, Last Run Date
                        else:
                            reg_report((name), str(x), str(y-5)) # UserAssist Values with invalid last run date
                    else:
                        reg_report((name)) # UserAssist Values with blank last run date
                else:
                    reg_report((name))# UserAssist Values CTLCUA and CTLSESSION

        report((""))


