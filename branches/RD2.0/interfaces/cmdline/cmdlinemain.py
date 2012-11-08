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

import os, sys, re, codecs
from optparse import OptionParser

import registrydecoder.registrydecoder as registrydecoder
import registrydecoder.handle_file_info as handle_file_info

import cmdline_display 

# this should be the only function to call print
# or to write to the terminal/output
def write_msg(message, die=0):
    print message 
    if die:
        sys.exit(1)

class cmdline_main:
    def _open_file_r(self, filename):
        try:
            fd = codecs.open(filename, "r", encoding="UTF-8")
        except:
            fd = None

        return fd

    def __init__(self):
        self._actions = {
              "list_fileids" : (self._parse_fileids_options,     self._perform_parse_fileids),
              "search"       : (self._parse_search_options,      self._perform_search_cmdline),
              "search_file"  : (self._parse_search_file_options, self._search_file),
              "plugins"      : (self._parse_plugin_options,      self._run_plugins_cmdline),
              "plugins_file" : (self._parse_plugin_file_options, self._plugins_file),
              "timeline"     : (self._parse_time_options,        self._run_timeline),
              "pathanalysis" : (self._parse_path_options,        self._run_pathanalysis),
              "create_case"  : (self._parse_create_case_options, self._create_case),
              }
        
        self.case_obj = None
        self.evidence_list = []
    
        self.last_option = ""

        self.report_obj = cmdline_display
    
        self.RD = registrydecoder.registrydecoder(self)

    def _parse_fileids_options(self, parser):
        pass

    # display the files/fileids associated with a case
    def _perform_parse_fileids(self, parser, args):
        fileinfo_hash = self.RD.handle_file_info.get_hives_info(self)[0]
              
        for fileid in fileinfo_hash:
            (filepath, evi_file, group_name) = self.RD.get_file_info(fileinfo_hash, fileid)
            print "%d -> %s" % (fileid, filepath)

    def _parse_path_options(self, parser):
        parser.add_option("-k", "--path_key",       dest="path_key",       help="key path to analyze",     default="") 
        parser.add_option("-K", "--paths_file",     dest="paths_file",     help="file of keys to analyze", default="")
        parser.add_option("-V", "--include_values", dest="include_values", help="Whether to include values in analysis (0/1)", default=1)

    def _run_pathanalysis(self, parser, args):
        include_values = self._parse_boolean_arg(args.include_values)
            
        pp = self.RD.pathbased.set_analysis_params(args.path_key, args.paths_file, include_values, args.start_date, args.end_date)

        if not pp:
            return        
 
        results = self.RD.pathbased.run_path_analysis(pp)

        self.RD.pathbased.write_path_results(results, self.report_format, self.report_filename)

    def _parse_time_options(self, parser):
        parser.add_option("-t", "--timeline_format", dest="timeline_format", help="Format to write timeline to (txt/tsv)", default="")
        parser.add_option("-T", "--timeline_file",   dest="timeline_file",   help="File to write timeline to")

    def _run_timeline(self, parser, args):
        if args.timeline_format != "" and args.timeline_format[0] != ".":
            args.timeline_format = "." + args.timeline_format
 
        tp = self.RD.timeline.set_timeline_params(args.timeline_file, args.timeline_format, args.start_date, args.end_date)

        if not tp:
            return

        self.RD.timeline.write_timeline(tp)    

    def _parse_plugin_file_options(self, parser):      
        parser.add_option("-F", "--plugins_file", dest="plugins_file", help="File of plugin options to analyze with ", default="")
 
    def _do_run_plugins(self, plugin_names):
        plugin_results = self.RD.plugins.run_plugins(plugin_names, self.perform_diff)

        self.RD.plugins.write_plugin_results(plugin_results, self.report_format, self.report_filename)

    # The file is simply a newline seperated list of plugins to run
    def _plugins_file(self, parser, args):
        fd = self._open_file_r(args.plugins_file)

        if fd == None:
            write_msg("Invalid plugins_file given.", die=True)

        plugin_names = []

        for name in fd.readlines():
            name = name.strip()
            plugin_names.append(name)

        self._do_run_plugins(plugin_names) 
 
    def _parse_plugin_options(self, parser):
        parser.add_option("-p", "--plugins", dest="plugins", help="Command seperate list of plugins to run", default="")

    def _run_plugins_cmdline(self, parser, args):
        if args.plugins == "":
            write_msg("No plugins (-p/--plugins) given to be run.")
            self._usage("plugins")
        
        plugin_names = [name.strip() for name in args.plugins.split(",")]   

        self._do_run_plugins(plugin_names)

    def _parse_search_options(self, parser):
        parser.add_option("-s",  "--searchterm",    dest="searchterm",    help="Single search term to be searched", default="")
        parser.add_option("-f" , "--searchfile",    dest="searchfile",    help="File of search terms",              default="")
        parser.add_option("-p",  "--searchpartial", dest="searchpartial", help="Search partial", action="store_true") 
        parser.add_option("-k",  "--searchkeys",    dest="searchkeys",    help="Search keys",    default=1)
        parser.add_option("-n",  "--searchnames",   dest="searchnames",   help="Search names ",  default=1)
        parser.add_option("-d",  "--searchdata",    dest="searchdata",    help="Search data",  default=1)
 
    def _parse_boolean_arg(self, arg):
        try:
            ret = int(arg)
        except:
            ret = arg

        return ret

    def _do_search(self, searchterm, searchfile, searchpartial, searchkeys, searchnames, searchdata, start_date, end_date):
        searchkeys  = self._parse_boolean_arg(searchkeys)
        searchnames = self._parse_boolean_arg(searchnames)
        searchdata  = self._parse_boolean_arg(searchdata)

        sp = self.RD.search.set_search_params(searchterm, searchfile, searchpartial, searchkeys, searchnames, searchdata, start_date, end_date)

        if not sp:
            return

        # a _search_report_info instance
        search_results = self.RD.search.perform_search(sp, self.perform_diff)

        # this handles writing to terminal or to a report file, based on self.report_format
        self.RD.search.write_search_results(search_results, report_format=self.report_format, report_filename=self.report_filename)

    def _perform_search_cmdline(self, parser, args):
        self._do_search(args.searchterm, args.searchfile, args.searchpartial, args.searchkeys, args.searchnames, args.searchdata, args.start_date, args.end_date)
         
    def _parse_search_file_options(self, parser):
        parser.add_option("-F", "--searchfile", dest="searchfile", help="File with search parameters", default="")

    '''
    search term
    search file
    partial (0/1)
    keys
    names
    values
    start_date
    end_date
    '''
    def _search_file(self, parser, args):
        if args.searchfile == "":
            write_msg("No search file (-F/--searchfile) given.")
            self._usage("searchfile")
        
        fd = self._open_file_r(args.searchfile)

        if not fd:
            write_msg("Unable to open search file.", die=True)
        
        vals = {"search_term"   : "",
               "search_file"    : "",
               "partial_search" : 0,
               "search_keys"    : 1,
               "search_names"   : 1,
               "search_values"  : 1,
               "start_date"     : "",
               "end_date"       : ""}
     
        ents = fd.readlines()
        
        for ent in ents:
            ent = ent.strip().split(":")

            if len(ent) != 2:
                write_msg("Invalid search file given.", die=True)
            
            (key, val) = ent

            if key in vals:
                # boolean_arg just returns the value if not an int
                vals[key] = self._parse_boolean_arg(val)
            else:
                write_msg("Unknown key in search file: %s. Cannont proceed." % key, die=True)
            
        self._do_search(vals["search_term"], vals["search_file"], vals["partial_search"], vals["search_keys"], vals["search_names"], vals["search_values"], vals["start_date"], vals["end_date"])
    
    def _parse_create_case_options(self, parser):
        parser.add_option("-F", "--casefile", dest="casefile", help="File with information on the created case", default="")

    '''
    Case Name
    Case Number 
    Investigator Name
    Comments
    Case Directory
    Active Files
    Backup Files
    Evidence Path 1
    ..
    Evidence Path N
    '''
    def _create_case(self, parser, args):
        if args.casefile == "":
            write_msg("No casefile specified")
            self._usage(parser, "create_case")            

        fd = self._open_file_r(args.casefile)

        if fd == None:
            write_msg("Unable to open new case configuration file.", die=True)

        regex = "[\r\t\n]"
        
        ents = [re.sub(regex, '', line) for line in fd.readlines()]

        if len(ents) < 6:
            write_msg("The given case configuration file is invalid: Less than the minimum of 6 lines long", die=True)

        # parse case info out of file and insert into database
        (case_name, case_num, case_investigator, case_comments, case_directory, acq_current, acq_backups) = ents[:7]
        
        self.acquire_current = int(acq_current) == 1
        self.acquire_backups = int(acq_backups) == 1

        # make directory if does not exist
        try:
            os.makedirs(case_directory)
        except:
            pass

        caseinfo = self.RD.createcase.set_case_info(case_name, case_num, case_investigator, case_comments, case_directory)
        self.RD.createcase.processCaseInfo(caseinfo)

        for line in ents[7:]:
            file_info = line.split("|")
            evidence_file = file_info[0]
            if len(file_info) > 1:
                alias = file_info[1]

            if not os.path.exists(evidence_file):
                write_msg("File: %s does not exist. Exiting." % evidence_file, die=True)
            
            self.evidence_list.append(evidence_file)
         
            # NIST_TODO
            # set alias

        self.RD.createcase.setupCaseDir()

        self.RD.createcase.process_case_files()        

    # NIST_TODO              
    def _usage(self, parser, action=""):
        if action == "":
            write_msg("Usage: python RD.py <action> <action args>. For help in a specific action type: python %s [%s]" % (sys.argv[0], ''.join([x + "," for x in self._actions.keys()])[:-1])) 
        
        elif action in self._actions:
            write_msg("GLOBAL OPTIONS")

            for option in parser.option_list:
                msg   = option.help
                short = option._short_opts
                default = option.default

                if default != None:
                    default = "%s" % str(default)
                    if len(default) > 0:
                        if str(default) == "('NO', 'DEFAULT')":
                            default = ""
                        else:
                            default = "- %s" % default

                write_msg("%-20s - %-30s %s" % (option, msg, default))
            
                if short[0] == self.last_option:
                    write_msg("PER-ANALYSIS OPTIONS")
        else:
            print "BUG!!!! invalid usage sent %s" % action
 
        sys.exit(1)

    def _parse_fileids_opt(self, fileids_opt):
        if fileids_opt == "":
            return None
        
        case_fileids = self.RD.handle_file_info.get_hives_info(self)[0].keys()

        user_fileids = fileids_opt.split(",")

        # fileid 0 only specifices to run on all files
        if len(user_fileids) == 1 and user_fileids[0] == "0":
            ret = case_fileids
        else:
            ret =  []
            for fileid in fileids_opt.split(","):
                fileid = int(fileid)

                # help the user out...
                if fileid not in case_fileids:
                    write_msg("Given fileid %d is not a valid file id for this case." % fileid, die=True)

                ret.append(fileid)
        
        return ret

    def _parse_report_format(self, format_opt):
        if format_opt == "":
            ret = ""
        else:
            report_types = self.RD.ref_rm.get_loaded_report_types()
           
            format_opt = format_opt.upper()
            if format_opt in report_types:
                ret = format_opt
            else:
                write_msg("Invalid report format given.")
                self._usage("report_format")
            
        return ret
    
    # this is only called if a file-based report was chosen, so filename must be set
    def _parse_report_filename(self, filename_opt):
        if filename_opt == "":
            write_msg("Report format %s chosen, but no output filename given." % self.report_format)
            self._usage("report_format")
        else:
            ret = filename_opt

        return ret
 
    def _get_default_parser(self):
        parser = OptionParser()

        parser.add_option("-c", "--casefolder",    dest="casefolder",    help="The case folder to analyze", default="")
        parser.add_option("-i", "--fileids",       dest="fileids",       help="Comma seperated list of fileids to analyze from the case folder", default="")
        parser.add_option("-r", "--report_format", dest="report_format", help="Format to write report (default is to terminal)", default="")
        parser.add_option("-o", "--output_file",   dest="output_file",   help="Output file to write report",                     default="")
        parser.add_option("-P", "--plugin_dirs",   dest="plugin_dirs",   help="Extra directory to load plugins from",            default="")
        parser.add_option("-b", "--before",        dest="end_date",      help="Filter results to entries before this date", default="")
        parser.add_option("-a", "--after",         dest="start_date",    help="Filter results to entries after this date",  default="")
        parser.add_option("-D", "--diff",          dest="perform_diff",  help="Perform diff analyais",  action="store_true")
        parser.add_option("-I", "--disable_input", dest="disable_input", help="Disable input (batch mode)", action="store_true")

        # this lets the usage message differeniate between global options and per-analysis type ones
        # needs to always be the last option added here
        self.last_option = "-D"

        return parser
    
    def _open_case(self, casefolder):
        if casefolder == "":
            return False

        try:
            files = os.listdir(casefolder)
        except OSError:
            write_msg("Unable to open the given case directory folder", die=True)

        files = set(files)
        needed_files = set(["caseobj.pickle", "evidence_database.db", "stringtable.db", "namedata.db"])

        # this directory is missing critical file(s)
        if needed_files.intersection(files) != needed_files:
            write_msg("The given directory is not a Registry Decoder case directory.", die=True) 

        o = self.RD.opencase

        o.opencase(casefolder)

        self.case_obj = o

        self.RD = registrydecoder.registrydecoder(self)

        return True

    def process_args(self, args):
        action = args[1]

        if action in self._actions:
            (action_opts, action_perform) =  self._actions[action]     
            
            parser = self._get_default_parser()
            action_opts(parser)

            (options, optargs) = parser.parse_args(args[2:])

            self.enable_input = not options.disable_input

            # setup global args for analysis
            if not action in ["create_case"]:
                if self._open_case(options.casefolder) == False:
                    write_msg("Mandatory casefile (-c/--casefolder) option missing.")
                    self._usage(parser, action)

                self.fileids = self._parse_fileids_opt(options.fileids)
                if self.fileids == None and action != "list_fileids":
                    write_msg("No file ID(s) specified. Cannot proceed.")
                    self._usage(parser, action)

                self.plugin_dirs = options.plugin_dirs

                self.report_format = self._parse_report_format(options.report_format)
                if self.report_format == "":
                    self.report_filename = ""
                else:
                    self.report_filename = self._parse_report_filename(options.output_file)
                
                self.perform_diff = options.perform_diff
                
                if self.perform_diff:
                    if len(self.fileids) != 2:
                        write_msg("Two fileids must be given when diff is chosen.")
                        self._usage("")
            
            action_perform(parser, options)
        else:
            write_msg("Invalid action given: %s" % action)
            self._usage("", "")

    def generate_plugin_results_tab(self, results):
        return None

    def generate_search_results_tab(self, _a, _b, _c, _d):
        return None

    def generate_path_results_tab(self, _a, _b, _c):
        return None

    def get_current_fileids(self, _action, max_fileids=-1):
        return self.fileids

    def yesNoDialog(self, msg, msg1):
        print msg

        answer = raw_input(msg1 + " ('yes' or 'no'): ")

        if answer == 'yes':
            ret = True
        elif answer == 'no':
            ret = False
        else:
            write_msg("Invalid answer given. Please write 'yes' or 'no'. ")
            ret = self.yesNoDialog(msg, msg1)

        return ret
    
    # fakes a message box by writing a message and waiting for input (Enter)
    def msgBox(self, msg):
        write_msg(msg)
        if self.enable_input == True:
            discard = raw_input("Press Enter to Proceed")

    # This can be suppressed or converted to only write one line    
    def updateLabel(self, msg):
        write_msg(msg)

# called when an error is triggered up to the global exception handler
def do_error_msg(message):
    write_msg(message)

def do_cmdline_main():

    obj = cmdline_main()
    args = sys.argv

    obj.process_args(args)
  

