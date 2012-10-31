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
import codecs, datetime

import registrydecoder.analysis.base as analysisBase
import registrydecoder.common as common
import registrydecoder.handle_file_info as handle_file_info

class _timeline_params:
    def __init__(self, outputfile, ext, fd, startDate, endDate):
        self.outputfile = outputfile
        self.ext        = ext
        self.fd         = fd
        self.startDate  = startDate
        self.endDate    = endDate

class timelineAnalysis(analysisBase.analysisBase):
    def __init__(self, UI):
        analysisBase.analysisBase.__init__(self, UI)

    def _valid_params(self, outputfile, ext, startDate, endDate):
        if not outputfile or len(outputfile) == 0:
            self.UI.msgBox("No timeline output file given.") 
            return None

        if not ext in [".txt", ".tsv"]:
            self.UI.msgBox("Invalid extension given, must be .txt or .tsv")
            return None

        if not outputfile.endswith(ext):
            outputfile = outputfile + ext
        
        try:
            fd = codecs.open(outputfile, "a+", encoding="UTF-8")
        except:
            self.UI.msgBox("Unable to open output file for writing.")
            return None

        ret = None
        if not startDate or common.parse_date(startDate):
            if not endDate or common.parse_date(endDate):
                ret = (fd, outputfile)
            else:
                self.UI.msgBox("Invalid end date given.")
        else:
            self.UI.msgBox("Invalid start date given.") 
         
        return ret

    def set_timeline_params(self, outputfile, ext, startDate, endDate):
        valid = self._valid_params(outputfile, ext, startDate, endDate)
        
        if valid:
            (fd, outputfile) = valid
            ret = _timeline_params(outputfile, ext, fd, startDate, endDate)
        else:
            ret = None

        return ret         

    def _run_timeline(self, tp, fileid):
        filepath = common.get_file_info(self.fileinfo_hash, fileid)[0]

        # walk each node of the tree looking for entries that belong to this fileid
        nodehash = self.tapi._get_tree().nodehash
        numnodes = len(nodehash)

        for idx in xrange(0, numnodes+2):
            idx = "%d" % idx

            if idx in nodehash:
                node = nodehash[idx]
            else:
                continue

            # ensure fileid is correct
            if fileid in node.fileids:
  
                # filter by dates 
                if tp.startDate or tp.endDate:
                    res = common.filter_results(self.UI, [node], fileid, tp.startDate, tp.endDate)
                else:
                    res = [1]

                if len(res) == 1:
                    path      = self.tapi.full_path_node_to_root(node)
                    lastwrite = node.timestamps[fileid] 

                    if tp.ext == ".tsv":
                        lastwrite = datetime.datetime.fromtimestamp(lastwrite).strftime('%Y/%m/%d %H:%M:%S')
                        tp.fd.write("%s\t%s\t%s\n" % (filepath, path, lastwrite))

                    elif tp.ext == ".txt":
                        # these three lines will write out autopsy format, regtime.pl
                        filepath = filepath.replace("|", ",")
                        tp.fd.write("0|%s:%s|0|0|0|0|0|0|%d|0|0\n" % (filepath, path, lastwrite))
                    else:
                        raise RDError("Invalid timeline extension passed validation: %s" % tp.ext)
                
    def write_timeline(self, tp):
        self.fileinfo_hash = handle_file_info.get_hives_info(self.UI)[0]

        fileids = self.UI.get_current_fileids("timeline")   
       
        for fileid in fileids:
            self._run_timeline(tp, fileid)

        tp.fd.close()

        self.UI.msgBox("Timeline Created")








    

