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
# Time Zone Information
#
# Kevin Moore - CERT - kevinm@cert.org



pluginname = "Time Zone Information"
description = "Displays information on current timezone settings"
hive = "SYSTEM"    

# Windows 7 values related to tzres.dll timezone resolution
# Values for Windows 7 are represented by a numeric code, this does the conversion to a friendly name
tz_dict = {10:'(UTC-01:00) Azores',
           11:'Azores Daylight Time',
           12:'Azores Standard Time',
           20:'(UTC-01:00) Cape Verde Is.',
           21:'Cape Verde Daylight Time',
           22:'Cape Verde Standard Time',
           30:'(UTC-02:00) Mid-Atlantic',
           31:'Mid-Atlantic Daylight Time',
           32:'Mid-Atlantic Standard Time',
           40:'(UTC-03:00) Brasilia',
           41:'E. South America Daylight Time',
           42:'E. South America Standard Time',
           50:'(UTC-03:00) Greenland',
           51:'Greenland Daylight Time',
           52:'Greenland Standard Time',
           60:'(UTC-03:00) Buenos Aires, Georgetown',
           61:'SA Eastern Daylight Time',
           62:'SA Eastern Standard Time',
           70:'(UTC-03:30) Newfoundland',
           71:'Newfoundland Daylight Time',
           72:'Newfoundland Standard Time',
           80:'(UTC-04:00) Atlantic Time (Canada)',
           81:'Atlantic Daylight Time',
           82:'Atlantic Standard Time',
           90:'(UTC-04:00) Santiago',
           91:'Pacific SA Daylight Time',
           92:'Pacific SA Standard Time',
           100:'(UTC-04:00) Caracas, La Paz',
           101:'SA Western Daylight Time',
           102:'SA Western Standard Time',
           103:'(UTC-04:00) Manaus',
           104:'Central Brazilian Daylight Time',
           105:'Central Brazilian Standard Time',
           110:'(UTC-05:00) Eastern Time (US & Canada)',
           111:'Eastern Daylight Time',
           112:'Eastern Standard Time',
           120:'(UTC-05:00) Bogota, Lima, Quito, Rio Branco',
           121:'SA Pacific Daylight Time',
           122:'SA Pacific Standard Time',
           130:'(UTC-05:00) Indiana (East)',
           131:'US Eastern Daylight Time',
           132:'US Eastern Standard Time',
           140:'(UTC-06:00) Saskatchewan',
           141:'Canada Central Daylight Time',
           142:'Canada Central Standard Time',
           150:'(UTC-06:00) Central America',
           151:'Central America Daylight Time',
           152:'Central America Standard Time',
           160:'(UTC-06:00) Central Time (US & Canada)',
           161:'Central Daylight Time',
           162:'Central Standard Time',
           170:'(UTC-06:00) Guadalajara, Mexico City, Monterrey',
           171:'Central Daylight Time (Mexico)',
           172:'Central Standard Time (Mexico)',
           180:'(UTC-07:00) Chihuahua, La Paz, Mazatlan',
           181:'Mountain Daylight Time (Mexico)',
           182:'Mountain Standard Time (Mexico)',
           190:'(UTC-07:00) Mountain Time (US & Canada)',
           191:'Mountain Daylight Time',
           192:'Mountain Standard Time',
           200:'(UTC-07:00) Arizona',
           201:'US Mountain Daylight Time',
           202:'US Mountain Standard Time',
           210:'(UTC-08:00) Pacific Time (US & Canada)',
           211:'Pacific Daylight Time',
           212:'Pacific Standard Time',
           213:'(UTC-08:00) Tijuana, Baja California',
           214:'Pacific Daylight Time (Mexico)',
           215:'Pacific Standard Time (Mexico)',
           220:'(UTC-09:00) Alaska',
           221:'Alaskan Daylight Time',
           222:'Alaskan Standard Time',
           230:'(UTC-10:00) Hawaii',
           231:'Hawaiian Daylight Time',
           232:'Hawaiian Standard Time',
           240:'(UTC-11:00) Midway Island, Samoa',
           241:'Samoa Daylight Time',
           242:'Samoa Standard Time',
           250:'(UTC-12:00) International Date Line West',
           251:'Dateline Daylight Time',
           252:'Dateline Standard Time',
           260:'(UTC) Dublin, Edinburgh, Lisbon, London',
           261:'GMT Daylight Time',
           262:'GMT Standard Time',
           270:'(UTC) Casablanca, Monrovia, Reykjavik',
           271:'Greenwich Daylight Time',
           272:'Greenwich Standard Time',
           280:'(UTC+01:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague',
           281:'Central Europe Daylight Time',
           282:'Central Europe Standard Time',
           290:'(UTC+01:00) Sarajevo, Skopje, Warsaw, Zagreb',
           291:'Central European Daylight Time',
           292:'Central European Standard Time',
           300:'(UTC+01:00) Brussels, Copenhagen, Madrid, Paris',
           301:'Romance Daylight Time',
           302:'Romance Standard Time',
           310:'(UTC+01:00) West Central Africa',
           311:'W. Central Africa Daylight Time',
           312:'W. Central Africa Standard Time',
           320:'(UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna',
           321:'W. Europe Daylight Time',
           322:'W. Europe Standard Time',
           330:'(UTC+02:00) Minsk',
           331:'E. Europe Daylight Time',
           332:'E. Europe Standard Time',
           333:'(UTC+02:00) Amman',
           334:'Jordan Daylight Time',
           335:'Jordan Standard Time',
           340:'(UTC+02:00) Cairo',
           341:'Egypt Daylight Time',
           342:'Egypt Standard Time',
           350:'(UTC+02:00) Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius',
           351:'FLE Daylight Time',
           352:'FLE Standard Time',
           360:'(UTC+02:00) Athens, Bucharest, Istanbul',
           361:'GTB Daylight Time',
           362:'GTB Standard Time',
           363:'(UTC+02:00) Beirut',
           364:'Middle East Daylight Time',
           365:'Middle East Standard Time',
           370:'(UTC+02:00) Jerusalem',
           371:'Jerusalem Daylight Time',
           372:'Jerusalem Standard Time',
           380:'(UTC+02:00) Harare, Pretoria',
           381:'South Africa Daylight Time',
           382:'South Africa Standard Time',
           383:'(UTC+02:00) Windhoek',
           384:'Namibia Daylight Time',
           385:'Namibia Standard Time',
           390:'(UTC+03:00) Kuwait, Riyadh',
           391:'Arab Daylight Time',
           392:'Arab Standard Time',
           400:'(UTC+03:00) Baghdad',
           401:'Arabic Daylight Time',
           402:'Arabic Standard Time',
           410:'(UTC+03:00) Nairobi',
           411:'E. Africa Daylight Time',
           412:'E. Africa Standard Time',
           420:'(UTC+03:00) Moscow, St. Petersburg, Volgograd',
           421:'Russian Daylight Time',
           422:'Russian Standard Time',
           430:'(UTC+03:30) Tehran',
           431:'Iran Daylight Time',
           432:'Iran Standard Time',
           433:'(UTC+03:00) Tbilisi',
           434:'Georgian Daylight Time',
           435:'Georgian Standard Time',
           440:'(UTC+04:00) Abu Dhabi, Muscat',
           441:'Arabian Daylight Time',
           442:'Arabian Standard Time',
           447:'(UTC+04:00) Baku',
           448:'Azerbaijan Daylight Time',
           449:'Azerbaijan Standard Time',
           450:'(UTC+04:00) Yerevan',
           451:'Caucasus Daylight Time',
           452:'Caucasus Standard Time',
           460:'(UTC+04:30) Kabul',
           461:'Afghanistan Daylight Time',
           462:'Afghanistan Standard Time',
           470:'(UTC+05:00) Ekaterinburg',
           471:'Ekaterinburg Daylight Time',
           472:'Ekaterinburg Standard Time',
           480:'(UTC+05:00) Islamabad, Karachi, Tashkent',
           481:'West Asia Daylight Time',
           482:'West Asia Standard Time',
           490:'(UTC+05:30) Chennai, Kolkata, Mumbai, New Delhi',
           491:'India Daylight Time',
           492:'India Standard Time',
           500:'(UTC+05:45) Kathmandu',
           501:'Nepal Daylight Time',
           502:'Nepal Standard Time',
           510:'(UTC+06:00) Astana, Dhaka',
           511:'Central Asia Daylight Time',
           512:'Central Asia Standard Time',
           520:'(UTC+06:00) Almaty, Novosibirsk',
           521:'N. Central Asia Daylight Time',
           522:'N. Central Asia Standard Time',
           530:'(UTC+05:30) Sri Jayawardenepura',
           531:'Sri Lanka Daylight Time',
           532:'Sri Lanka Standard Time',
           540:'(UTC+06:30) Yangon (Rangoon)',
           541:'Myanmar Daylight Time',
           542:'Myanmar Standard Time',
           550:'(UTC+07:00) Krasnoyarsk',
           551:'North Asia Daylight Time',
           552:'North Asia Standard Time',
           560:'(UTC+07:00) Bangkok, Hanoi, Jakarta',
           561:'SE Asia Daylight Time',
           562:'SE Asia Standard Time',
           570:'(UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi',
           571:'China Daylight Time',
           572:'China Standard Time',
           580:'(UTC+08:00) Irkutsk, Ulaan Bataar',
           581:'North Asia East Daylight Time',
           582:'North Asia East Standard Time',
           590:'(UTC+08:00) Kuala Lumpur, Singapore',
           591:'Malay Peninsula Daylight Time',
           592:'Malay Peninsula Standard Time',
           600:'(UTC+08:00) Taipei',
           601:'Taipei Daylight Time'}


def run_me():
    
    from datetime import time
    import struct
    
    def convert_start_date(raw_data):
        
        months       = {1:'Jan', 2:'Feb', 3:'Mar', 4:'Apr', 5:'May', 6:'Jun', 7:'Jul', 8:'Aug',
                        9:'Sep', 10:'Oct', 11:'Nov', 12:'Dec'}
        days         = {0:'Sunday', 1:'Monday', 2:'Tuesday', 3:'Wednesday', 4:'Thursday', 5:'Friday', 6:'Saturday'}
        weeks        = {1:'1st', 2:'2nd', 3:'3rd', 4:'4th', 5:'Last'}
        
        year,        = struct.unpack('H', raw_data[0:2])                      
        month,       = struct.unpack('H', raw_data[2:4])                  # See dictionary above for conversion
        week,        = struct.unpack('H', raw_data[4:6])                  # See dictionary above for conversion
        hour,        = struct.unpack('H', raw_data[6:8])
        minute,      = struct.unpack('H', raw_data[8:10])
        seconds,     = struct.unpack('H', raw_data[10:12])
        milli,       = struct.unpack('H', raw_data[12:14])
        day_of_week, = struct.unpack('H', raw_data[14:16])                # See dictionary above for conversion
        
        entry_time   = time(hour,minute,seconds,milli)                # retrieves time object as %H%M%S
        
        return weeks[week] + ' ' + days[day_of_week] + ' in ' + months[month] \
               + ' at ' + entry_time.strftime('%H:%M:%S')           # returns string of Start (Standard or Daylight) date/time        
    
    # ENDFUNCTION - convert_start_date
    
    ccs = reg_get_currentcontrolset()                               # Identifies system's current control set for timezone settings retrieval
    reg_report(('Current ControlSet', '00' + ccs))
    
    regkey = reg_get_required_key("\ControlSet00" + ccs + "\Control\TimeZoneInformation")   # Retrieves key based on CurrentControlSet
    values = reg_get_values(regkey)
    
    for val in values:
        
        if reg_get_value_name(val) == 'StandardStart' or reg_get_value_name(val) == 'DaylightStart':   # Require conversion based on convert_start_date function
            
            date = convert_start_date(reg_get_raw_value_data(val))
            reg_report((reg_get_value_name(val), date))
            
        elif (reg_get_value_name(val) == 'DaylightName' or reg_get_value_name(val) == 'StandardName') and reg_get_value_data(val).startswith('@tzres.dll'):
            
            tz_val = reg_get_value_data(val).split(',')[1]
            tz_val = tz_val.lstrip('-')
            reg_report((reg_get_value_name(val), reg_get_value_data(val) + ' --> ' + tz_dict[int(tz_val)]))
            
        else:
            
            reg_report((reg_get_value_name(val),reg_get_value_data(val)))                              # Otherwise just print the value name and data

