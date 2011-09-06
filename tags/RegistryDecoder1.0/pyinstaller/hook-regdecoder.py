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
    

def collect_modules(path):

    projpath = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    modules = set([fullmod])

    (one, two) = fullmod.split(".") 

    for dirpath, _dirnames, filenames in os.walk(os.path.join(projpath, one, two)):
        dirpath = dirpath[len(os.path.join(projpath, one, two)):]
        if dirpath and dirpath[0] == os.path.sep:
            dirpath = dirpath[1:]
        for filename in filenames:
            path = os.path.join(dirpath, os.path.splitext(filename)[0])
        if "/." in path:
            continue
        # why?
        if "__" in path:
            continue

        path = path.replace("-", "_")
        path = path.replace(os.path.sep, ".")

        modules.add(fullmod + "." + path)

    hiddenimports = list(modules)

    return hiddenimports


hi = collect_modules("reporting.report_formats")

hi = hi + collect_modules("templates.template_files")

hiddenimports = list(hi)


