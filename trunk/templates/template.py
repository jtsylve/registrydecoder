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
# template.py

import util.util as tapi

class Template():

    '''
    Class template models a single template for use with regdecoder. This needs
    to handle textfile templates, as well as hand coded templates.
    
    Either way, the result should be template objects. In a list. 
    
    Need a registry api allowing others to easily code templates which are 
    more complex than can be handled by text templates.
    
    Test for key, value name:data existence 
    Enumerate sub-keys
    Enumerate values
    Set arbitrary display strings
    Timestamp decoding
    
    '''

    def __init__(self, name="", description="", required_keys=[], \
                    required_value_names=[], required_value_data=[], \
                    display_string="", hive="", oslevel=""):
        self.name = name                        # template name
        self.description = description            # description string
        self.required_keys = required_keys        # keys which must exist for me to be satisfied
        self.required_value_names = required_value_names    # as above but for value names
        self.required_value_data = required_value_data        # as above but for value data
        self.display_string = display_string    # what to display if template satisfied
        self.hive = hive                        # which hive file: NTUSER, SYSTEM, SOFTWARE, SAM, SECURITY
        self.oslevel = oslevel                    # what OS I am valid for
        
        self.tapi = tapi.templateutil()
        
    def __str__(self):
        result = "Name:\t\t%s\n" % (self.name) +\
        "Description:\t%s\n" % (self.description) +\
        "Required Keys:\n"
        for elem in self.required_keys:
            result += "\t" + str(elem) + "\n"
        result += "RequiredValueNames:\n"
        for elem in self.required_value_names:
            result += "\t %s %s \n" % (elem[0], elem[1])
        result += "RequiredValueData:\n"
        for elem in self.required_value_data:
            result += "\t %s %s %s \n" % (elem[0], elem[1], elem[2])
        result += "Display: " + self.display_string + "\n"
        result += "Hive: " + self.hive + "\n"
        result += "OS Level: " + self.oslevel + "\n"
        return result
        

    # Used for dynamic report generation when running tempates.
    def report(self, rep_string):
        self.display_string += rep_string + "\n"

    # generic 'set' functions for each attribute
    def set_name(self, name):
        self.name = name
    
    def set_description(self, desc):
        self.description = desc

    def add_required_key(self, key):
        self.required_keys.append(key)
        
    def add_required_value_name(self, key, name):
        #print("%s %s") % (key, name)
        self.required_value_names.append((key, name))
        
    def add_required_value_data(self, key, name, data):
        #print("printing: %s %s %s") % (key, name, data)
        self.required_value_data.append((key, name, data))
    
    def set_display_string(self, d_string):
        self.display_string = d_string
        
    def set_hive(self, hive):
        self.hive = hive
    
    def set_oslevel(self, oslevel):
        self.oslevel = oslevel
    
    def get_time(self, key):
        print key
        return "Sat, Dec 4, 2010"
    
        
    # what do we want our API to look like???    
    # API users need to be able to
    #     instantiate a new template
    #     set_*
    #    register it for use 
    #    determine if key exists
    #    get subtrees
    #    format output (description) strings
        
    # API Functions
    
    
    
    
        
