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
import sys, os, datetime, codecs, getopt

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

import registrydecoder.handle_file_info as handle_file_info

# the forms...
# DO NOT CHANGE THESE WITHOUT TELLING ANDREW
START_PAGE      = 0
LOAD_CASE       = 1
CASE_INFO       = 2
ADD_EVIDENCE    = 3
VIEW_SUMMARY    = 4
PROGRESS_LABEL  = 5
CASE_WINDOW     = 6

rolenum = 32

class RDMessageBox(QWidget):

    def __init__(self, app, msg, parent=None):
        QWidget.__init__(self, parent)

        self.app = app

        self.setGeometry(300, 300, 250, 150)
        QMessageBox.warning(self, 'Registry Decoder', msg)
 
    def closeEvent(self, event):
        pass

class RDMessageBoxInfo(QWidget):

    def __init__(self, app, msg, parent=None):
        QWidget.__init__(self, parent)

        self.app = app

        self.setGeometry(300, 300, 250, 150)
        QMessageBox.information(self, 'Registry Decoder', msg)
 
    def closeEvent(self, event):
        pass

def fill_tree(gui, tree_name, draw=1):
    # PERFORMANCE cache root
    (fileinfo_hash, root) = handle_file_info.get_hives_info(gui)

    if draw:
        do_draw_tree(gui, tree_name, root)

    return fileinfo_hash

def add_entry(parent, ent):

    #print "setting %s with fileids: %s" % (ent.name, str(ent.fileids))

    w = QTreeWidgetItem(parent)
    w.setText(0, ent.name)
    w.setData(0, rolenum, ent.fileids)

    return w

def do_draw_tree(gui, tree_name, root):
    
    # top level "All Files" widget and entry
    p = gui.__getattribute__(tree_name)
    w = add_entry(p, root)

    cur = root
    widget = w

    # each evidence file
    for imgent in root.subs:
        part = add_entry(w, imgent)

        # each partition
        for pent in imgent.subs:
            group = add_entry(part, pent)
           
            # each group
            for gent in pent.subs:
                rtype = add_entry(group, gent)

                # either file or RP###
                for outer in gent.subs:
                    o = add_entry(rtype, outer)

                    for inner in outer.subs:
                        u = add_entry(o, inner)
                
                        for x in inner.subs:
                            add_entry(u, x)

# gets fileid of every file chosen in the GUI
def get_reg_fileids(self, treename):

    all_fileids = []

    # QList<QTreeWidgetItem *>
    selectedFiles = self.__getattribute__(treename).selectedItems()

    if len(selectedFiles) == 0:
        self.msgBox("No registry hive was selected. Unable to process.")
        return None
        
    # QTreeWidgetItem
    for selFile in selectedFiles:

        for idx in xrange(0, selFile.columnCount()):

            fileids = selFile.data(idx, rolenum).toStringList()
            #print "%d -> %s -> %s" % (idx, selFile.text(idx), str(fileids)) 
               
            # build a big list of all fileids, can be duplicates
            for fileid in fileids:
                all_fileids.append(int(fileid))
          
    
    # ensure only unique files
    ret = list(set(all_fileids))

    #print "returning %s" % str(ret)

    return ret

# get files ids from a tree, enforce number of files allowed to be choosen
def get_file_ids(self, tree_name, allowed_files=-1):

    fileids = get_reg_fileids(self, tree_name) 

    # error msgbox will be generated in get_reg_fileids
    if not fileids:
        return None
    
    if allowed_files != -1 and len(fileids) != allowed_files:
        # this can be generalized later if we need to, right now only used for diffing
        self.gui.msgBox("Only one file can be picked per tree in diff mode. Cannot Proceed.")
        return None
    
    return fileids

def run_cb_on_tree(self, cb, sp, tree_name, max_allowed=-1):
        
    gen_tab  = 0
    results  = []

    fileids = self.gcommon.get_file_ids(self, tree_name, max_allowed)

    if fileids == None:
        return None

    for fileid in fileids:
        
        # get search results for file
        results = results + [cb(fileid, sp)]

    return results

def diffBoxClicked(self, isChecked, tree_name):      
       
    widget = self.gui.__getattribute__(tree_name)

    # if its checked then show the diff tree and fill it 
    if isChecked:
        widget.show()
        widget.clear()
        self.diff_fileinfo_hash = self.gcommon.fill_tree(self.gui, tree_name)            
    else:
        widget.hide()

def hide_tab_widgets(tab):

    # only hide the report format and drop down box
    tab.pushbutton.hide()
    tab.reportname.hide()
    tab.cbox.hide()
    tab.label1.hide()
    tab.label2.hide() 

def setup_diff_report(self, tab, orig_only, diff_only, common_elements):
    global global_gui

    global_gui = self.gui
    
    # save the lists for exporting
    tab.orig_only = orig_only
    tab.diff_only = diff_only
    tab.common    = common_elements

    tab.cbox.hide()
    tab.label1.hide()

def write_diff(fd, ents, char):

    # for each entry in the list
    for ent in ents:

        if not ent:
            continue

        val = char + " "

        if type(ent) == list or type(ent) == tuple:

            for item in ent:
                val = val + str(item) + "\t"

        # a searchmatch from the search tab
        elif hasattr(ent, "node"):
            
            val = val + "%s\t%s\t%s" % (ent.node.fullpath, ent.name, ent.data)
        
        elif type(ent) == int:

            val = val + "%d" % ent

        else:
            print "ent: unknown type: %s | %s" % (type(ent), str(ent))

        val = val[:-1] + "\n"

        fd.write(val)

def createDiffReport():
        
    curtab = global_gui.analysisTabWidget.currentWidget()
    
    fname = curtab.reportname.text()
        
    if not fname:
        global_gui.msgBox("No filename given for diff exporting.")
        return

    filename = str(fname)

    if not filename.endswith(".txt"):
        filename = filename + ".txt"
    
    fd = codecs.open(filename, "w+", encoding="UTF-8")  
    
    write_diff(fd, curtab.orig_only, "<")
    write_diff(fd, curtab.common,    "=")
    write_diff(fd, curtab.diff_only, ">")

    fd.close()

########################################## 
#     right click menu stuff             #
##########################################
class action_handler:
    def __init__(self, ref_obj, widget, message, error_no_path, provides_path=0):
        self.ref_obj = ref_obj
        self.widget  = widget
        self.message = message
        self.provides_path = provides_path
    
        # this controls whether to break if path is not found
        # right clicking from file view means its broken
        # searching a path could not be there...
        self.error_no_path = error_no_path

        self.tapi = self.ref_obj.gui.RD.search.tapi
 
    def get_current_row_node(self):
        curtab = self.ref_obj.gui.analysisTabWidget.currentWidget()
        
        self.ref_obj.gui.case_obj.current_fileid = curtab.fileid

        table      = curtab.searchResTable

        row        = table.currentRow()

        # get the key column no matter which the user picked
        item       = table.item(row, 1)

        fullpath   = unicode(item.text())

        node = self.tapi.root_path_node(fullpath)[-1]

        return node

    def setup_menu(self):

        self.widget.setContextMenuPolicy( Qt.CustomContextMenu )
        self.ref_obj.gui.connect(self.widget, SIGNAL('customContextMenuRequested(QPoint)'), self.on_context_menu)

        actionAdd = QAction(QString(self.message), self.widget) 

        self.popMenu = QMenu(self.widget)
        self.popMenu.addAction(actionAdd)

        self.ref_obj.gui.connect(actionAdd, SIGNAL("triggered()"), self.on_action_fileview)

    # setups right clicking on table cells
    def on_context_menu(self, point):
       
        curtab = self.ref_obj.gui.stackedWidget.currentWidget()

        self.popMenu.exec_( curtab.mapToGlobal(point) )
   
    # this is really ugly
    # sets a tree to a position based on a search hit
    def on_action_fileview(self):
  
        if self.provides_path == 1:
            node = self.get_current_row_node()
        else:
            node = get_tree_node(self.ref_obj)     

        if not node:
            if self.error_no_path == 1:
                raise RDError("Unable to get node for search to file view")
            else:
                self.ref_obj.gui.msgBox("The given path could not be found in the tree.")
                return 
                    
        nodes = self.tapi.node_to_root(node) + [node]

        if self.error_no_path == 1:
            tab = self.ref_obj.gui.filetab.viewTree([self.ref_obj.gui.case_obj.current_fileid])         
        else:
            # already have a tree..
            tab = self.ref_obj.gui.analysisTabWidget.currentWidget()
                    
        tree  = tab.viewTree
        model = tree.model()

        index = None
        bad   = 0
    
        for node in nodes[1:]:
            
            name = self.tapi.key_name(node)

            index = self.find_index(node, model, index)

            if not index:

                if self.error_no_path == 1:
                    raise RDError("BAD:: no index for %d | %s" % (node.nodeid, name))
                
                bad = 1
                break
     
        if not bad and index:
            tree.setCurrentIndex(index)
        else:
            self.ref_obj.gui.msgBox("The given path could not be found in the tree.")    

    # find where to jump in tree       
    def find_index(self, target_node, model, start_index=None):
        ret = None

        if not start_index:
            start_index = QModelIndex()

        rowcount = model.rowCount(start_index)

        for i in xrange(0, rowcount):
            p = model.index(i, 0, start_index)

            ent  = p.internalPointer()
            node = self.tapi.idxtonode(ent.nid)

            if node.nodeid == target_node.nodeid:
                ret = p
                break

        return ret

def parse_cmdline(gui, args):
    try:
        opts, args = getopt.getopt(sys.argv[1:], "d:", ["directory="])
    except getopt.GetoptError, err:
        print "usage: python guimain.py"
        print "optional argument: (-d/--directory) to specify an extra plugin directory"
        sys.exit(1)

    directories = ""
   
    for o, a in opts:

        if o in ("-d", "--directory"):  
            directories = a

    if directories:
        gui.plugin_dirs = directories.split(";")
    else:
        gui.plugin_dirs = []
 
     



