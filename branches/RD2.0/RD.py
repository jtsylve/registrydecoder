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

import sys, os, cProfile
import stat, time, cStringIO
import traceback

profile = 0

# If we're in a pyinstaller executable, from volatility
if hasattr(sys, "frozen"):
    try:
        import iu, _mountzlib
        mei = os.path.abspath(os.environ["_MEIPASS2"])
        sys.path.append(mei)
        os.environ['PATH'] = mei + ";" + os.environ['PATH']
    except ImportError:
        pass

import registrydecoder
import registrydecoder.errorclasses

interface = None

# taken from ERIC IDE since QT does not throw exceptions internally
def excepthook(excType, excValue, tracebackobj):
    global interface

    if excType == registrydecoder.errorclasses.MsgBoxError:
        errorbox = QMessageBox()
        errorbox.setWindowTitle(str("Registry Decoder"))
        errorbox.setText(str(excValue))
        errorbox.exec_()
        return
 
    dirname = os.getcwd()
    logfilename = os.path.join(dirname, "registry-decoder-error.txt")

    separator = "-" * 80

    notice = "An error has occurred and the details have been written to %s. Please send this file to registrydecoder@digdeeply.com so that we may address the issue." % (logfilename)
    
    timeString = time.strftime("%Y-%m-%d, %H:%M:%S")
        
    tbinfofile = cStringIO.StringIO()
    traceback.print_tb(tracebackobj, None, tbinfofile)
    tbinfofile.seek(0)
    tbinfo = tbinfofile.read()

    errmsg = '%s: \n%s' % (str(excType), str(excValue))

    sections = [separator, timeString, separator, errmsg, separator, tbinfo]

    msg = '\n'.join(sections)
    try:
        logfile = open(logfilename, "a+")
        logfile.write(msg)
        logfile.close()

    except IOError:
        pass

    if interface:
        interface.do_error_msg(notice)
    # this only happens in very early errors, e.g. one of the initial files imported throws an exception
    else:
        print notice

    sys.exit(1)

sys.excepthook = excepthook

# interfaces this file supports
import interfaces
import interfaces.cmdline.cmdlinemain as cmdlinemain
import interfaces.GUI.guimain as GUI

def gui_main():
    global interface
    interface = interfaces.GUI.guimain
    
    if profile:
        cProfile.run('interface.do_gui_main()')
    else:
        interface.do_gui_main()

def cmdline_main():
    global interface
    interface = interfaces.cmdline.cmdlinemain

    if profile:
        cProfile.run('interface.do_cmdline_main()')
    else:
        interface.do_cmdline_main()

def main():

    # the GUI takes no command line options
    if len(sys.argv) > 1:
        cmdline_main()
    else:
        gui_main()
   
if __name__ == "__main__":
    main()   





