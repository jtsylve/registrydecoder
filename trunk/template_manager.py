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
import os, sys
import templates
import templates.util.util as tutil

class TemplateManager:

    def __init__(self, template_directory="template_files"):
            
        self.template_directory = os.path.join("templates", template_directory)
        self.templates = []    
        sys.path.append(self.template_directory)
        
        self.timestamp = None

        self.reset_report()

    # return the template instance or None
    def find_template(self, template):

        ret = [t for t in self.templates if t.pluginname == template]

        if ret:
            ret = ret[0]

        return ret

    # Returns the list of all loaded templates.
    def get_loaded_templates(self):
        return self.templates

    # Returns the list of loaded templated which run on the specified hive 
    # ("System", "Software" ...)
    def get_hive_templates(self, hive):
        return [t for t in self.templates if hive in t.hives]
    
    def reset_report(self):
        self.report_data = []
        self.error_set = 0   
        self.plugin_set_header = 0

    # build a list of list of header/data value for reporting modules
    def set_report_header(self, header, psetheader=1):

        if psetheader == 1:
            self.plugin_set_header = 1

        if isinstance(header, str) or isinstance(header, unicode):
            header = [header]

        self.report_data.append(header)

    # how templates report their output, a list of lists to the caller
    def report(self, data):

        self.set_report_header(data, 0)

    def report_error(self, data):

        self.error_set = 1

        # if there is a header keep it    
        if self.plugin_set_header == 1:
            self.report_data = [self.report_data[0], [data]]

        # if not indicate error
        else:
            self.report_data = [["Plugin Error"], [data]]

    def set_timestamp(self, timestamp):
        self.timestamp      = timestamp

    def attach_template_methods(self, mod, case_obj):
                
        tree = case_obj.tree
        tapi = tutil.templateutil(case_obj)

        # lets templates call report directly
        tapi.report = self.report

        # lets templates set the global timestamp
        tapi.set_timestamp = self.set_timestamp

        # attach methods from templaute utils
        for attr in  tutil.templateutil.__dict__:
            if attr[0:2] != "__":
                method_addr = getattr(tapi, attr)
                setattr(mod, attr, method_addr)
        
    def attach_string_methods(self, mod, case_obj):
        
        setattr(mod, "get_key_string",   case_obj.tree.stringtable.nodetostr)
        setattr(mod, "get_value_string", case_obj.vtable.get_value_string)
        setattr(mod, "get_name_string",  case_obj.vtable.get_name_string)

    def attach_report_methods(self, mod, case_obj):

        setattr(mod, "report",            self.report)
        setattr(mod, "report_error",      self.report_error)
        setattr(mod, "reg_set_report_header", self.set_report_header)

    def attach_methods(self, mod, case_obj):

        self.attach_template_methods(mod, case_obj)
        self.attach_string_methods(mod, case_obj)
        self.attach_report_methods(mod, case_obj)

   # Walk the template directory and parse each file into a Template.
    def load_templates(self, case_obj, extra_dirs):
        
        self.templates = []
    
        if '_MEIPASS2' in os.environ:
            self.template_directory = os.path.join(os.environ['_MEIPASS2'], "templatess")
            sys.path.append(self.template_directory)
       
        self.import_templates(case_obj, self.template_directory)
        
        for directory in extra_dirs:

            sys.path.append(directory)
            self.import_templates(case_obj, directory)

    def import_templates(self, case_obj, directory):

        required_attrs = ["pluginname", "description", "run_me"]

        for root, dirs, files in os.walk(directory):
            for fd in files:
                
                if fd.endswith(".py") or fd.endswith(".PY"):
                    # these are python api templates which we need to load
                    # modules must define everything in required_attrs

                    # get module name from filename
                    modname = fd.rsplit(".")[0]
                    
                    mod = __import__(modname)

                    valid = 1
                    # verify it meets requirements
                    for attr in required_attrs:
                        if not hasattr(mod, attr):
                            valid = 0
                
                    if valid:

                        # allows plugins to work on multiple hive types                                                
                        if hasattr(mod, "hive"):
                            setattr(mod, "hives", [mod.hive])
                            delattr(mod, "hive")

                        self.attach_methods(mod, case_obj)
                        self.templates.append(mod)
                            
# see opencase.py -> main() 
# on how to use/run/load templates

    
