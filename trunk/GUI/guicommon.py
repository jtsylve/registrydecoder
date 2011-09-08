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
import sys, os, sqlite3

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *


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


# tree displayed of registry files to be analyzed
class tree_entry:
    
    def __init__(self, name):
        # all the file ids in the tree
        self.fileids = []
        self.subs  = []
        self.name    = name

class rfileinfo:

    def __init__(self, evidence_file, alias, reg_file, reg_type, hashvalue, mtime, group_name):

        self.evidence_file = evidence_file
        self.alias         = alias
        self.reg_file      = reg_file
        self.reg_type      = reg_type
        self.hashvalue     = hashvalue
        self.mtime         = mtime
        self.group_name    = group_name

def get_ename(efile, alias):

    if alias:
        ename = alias
    else:
        ename = efile

    return ename

def fill_tree(gui, tree_name):

    # PERFORMANCE cache root
    (fileinfo_hash, root) = do_fill_tree(gui)

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

    # each evidence file
    for fent in root.subs:
        fent.name = fent.name
        f = add_entry(w, fent)

        # each group
        for gent in fent.subs:

            if gent.name == "SINGLE":
                continue

            g = add_entry(f, gent)
            
            # each file
            for rent in gent.subs:
                unused = add_entry(g, rent)

def do_fill_tree(gui):

    fileinfo_hash = {}

    # hash kept to make display code sane
    root = tree_entry("All Files")

    cursor = gui.case_obj.evidencedb.cursor
    cursor.execute("select filename, file_alias, id from evidence_sources")

    files  = cursor.fetchall()
    
    # for every evidence file
    for (evidence_file, alias, efileid) in files:
   
        ename = get_ename(evidence_file, alias)

        efile = tree_entry(ename)

        root.subs.append(efile)

        cursor.execute("select group_name, id from file_groups where evidence_file_id=?",[efileid])
        groups = cursor.fetchall()
        
        for (group_name, gid) in groups:

            gent = tree_entry(group_name)
            efile.subs.append(gent)

            # get all the files from a group
            cursor.execute("select filename, id, registry_type, md5sum, mtime from registry_files where group_id=?", [gid])
            regfiles = cursor.fetchall()

            for (rfile, fileid, rtype, md5sum, mtime) in regfiles:
                
                fent = tree_entry(rfile)
                gent.subs.append(fent)

                fileinfo_hash[fileid] = rfileinfo(evidence_file, ename, rfile, rtype, md5sum, mtime, group_name) 
    
                root.fileids.append(fileid)
                efile.fileids.append(fileid)
                gent.fileids.append(fileid)
                fent.fileids.append(fileid)

    return (fileinfo_hash, root)

# gets fileid of every file chosen in the GUI
def get_reg_fileids(self, treename):

    all_fileids = []

    # QList<QTreeWidgetItem *>
    selectedFiles = self.gui.__getattribute__(treename).selectedItems()

    #print "%d files selected" % len(selectedFiles)

    if len(selectedFiles) == 0:
        self.gui.msgBox("No registry hive was selected. Unable to process.")
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

def get_file_info(finfo):

    filepath   = finfo.reg_file
    alias      = finfo.alias
    evi_file   = finfo.evidence_file
    group_name = finfo.group_name 

    if group_name != "SINGLE":
        filepath = "%s from %s" % (filepath, evi_file)

    # if an alias was given
    if len(alias) and evi_file != alias:
        filepath = filepath + " ( %s )" % alias

    return (filepath, evi_file, group_name)
    
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

    tab.pushbutton.hide()
    tab.reportname.hide()
    tab.cbox.hide()
    tab.label1.hide()
    tab.label2.hide() 

 # python diffing lists of objects is strange.. do it our own
def my_diff(one, two):

    ret = []

    for o in one:
        if not o in two: 
            ret.append(o)

    return ret

# returns the difference of the lists
def diff_lists(orig_results, new_results):

    # get the differences between the two
    orig_only = my_diff(orig_results, new_results)
    new_only  = my_diff(new_results, orig_results)

    # the middle view
    orig_results = my_diff(orig_results, orig_only)

    return (orig_only, new_only, orig_results)

# returns a list of the legenth of data_list elements
def get_idxs(data_list):

    idxs = []
    
    i = 0
    
    for d in data_list:

        l = len(d)
        #if l != 0 and i > 0:
        #    l = l -1
            
        idxs.append(l)
        i = i + 1
        
    return idxs

########################################## 
#     right click menu stuff             #
##########################################


class action_handler:

    def __init__(self, ref_obj, widget, message, error_no_path):

        self.ref_obj = ref_obj
        self.widget  = widget
        self.message = message
    
        # this controls whether to break if path is not found
        # right clicking from file view means its broken
        # searching a path could not be there...
        self.error_no_path = error_no_path
 
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
   
        node = self.ref_obj.get_tree_node()     

        if not node:
            if self.error_no_path == 1:
                raise RDError("Unable to get node for search to file view")
            else:
                self.ref_obj.gui.msgBox("The given path could not be found in the tree.")
                return 
                    
        nodes = self.ref_obj.tapi.node_to_root(node) + [node]

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
            
            name = self.ref_obj.tapi.key_name(node)

            index = self.find_index(node, model, index)

            if not index:

                if self.error_no_path == 1:
                    raise RDError("BAD:: no index for %d | %s" % (node.nodeid, name))
                
                bad = 1
                break
     
        if not bad:
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
            node = self.ref_obj.tapi.idxtonode(ent.nid)

            if node.nodeid == target_node.nodeid:
                ret = p
                break

        return ret

 
















