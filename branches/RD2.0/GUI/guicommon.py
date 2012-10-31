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
import sys, os, datetime, codecs

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

from errorclasses import *

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

class search_results:

    def __init__(self, filepath, evi_file, group_name, results, fileid):

        self.filepath   = filepath
        self.evi_file   = evi_file
        self.group_name = group_name
        self.results    = results 
        self.fileid     = fileid

    # compare based on the search results only..
    def __cmp__(self, other):
        return self.results == other.results

    def __hash__(self):
        return hash(str(self.results))
# get the users date in the form of mm/dd/yyyy
def parse_date(self, dateStr, datetype):

    e = [x for x in dateStr.split("/")]

    if len(e) != 3:
        self.gui.msgBox("Invalid %s date given." % datetype)
        ret = None
    else:
    
        try:
            ents = [int(x) for x in e]
        except:
            self.gui.msgBox("Invalid %s date given." % datetype)
            ret = None
        else:
            # v1 way -- didn't make sense since last write time in browse were different format
            #(month, day, year) = ents
            (year, month, day) = ents
            ret = QDate(year, month, day)

    return ret

# filter search results based on the user's choosen start and end last written dates
def filter_results(self, results, fileid, startStr, endStr):

    # the filtered set
    ret = []

    if startStr:
        start = parse_date(self, startStr, "start")
        if start == None:
            return None
    else:
        start = ""

    if endStr:
        end = parse_date(self, endStr, "end")
        if end == None:
            return None
    else:
        end = ""

    for row in xrange(len(results)):

        r = results[row]

        # convert last written time to QDate for easy comparison to user supplied choice
        if hasattr(r, "node"):
            node = r.node
        else:
            node = r

        timestamp = node.timestamps[fileid]
        c = datetime.datetime.fromtimestamp(timestamp)
        cmpQDate = QDate(c.year, c.month, c.day)

        # this allows for narrowing by both start and end or just 1 at at ime
        if start and end:
            append = start <= cmpQDate <= end
        
        elif start:
            append = start <= cmpQDate

        elif end:
            append = end >= cmpQDate                
        
        if append:
            ret.append(r)

    return ret

# tree displayed of registry files to be analyzed
class tree_entry:
    
    def __init__(self, name):
        # all the file ids in the tree
        self.fileids = []
        self.subs  = []
        self.name    = name

class rfileinfo:

    def __init__(self, evidence_file, alias, reg_file, reg_type, hashvalue, mtime, group_name, part_num, type_name, rpname=""):

        self.evidence_file = evidence_file
        self.alias         = alias
        self.reg_file      = reg_file
        self.reg_type      = reg_type
        self.hashvalue     = hashvalue
        self.mtime         = mtime
        self.group_name    = group_name
        self.part_num      = part_num
        self.type_name     = type_name
        self.rp_name       = rpname

def get_ename(efile, alias):

    if alias:
        ename = alias
    else:
        ename = efile

    return ename

def fill_tree(gui, tree_name, draw=1):

    # PERFORMANCE cache root
    (fileinfo_hash, root) = do_fill_tree(gui)

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

def do_fill_tree(gui):

    # do not change the order of these!
    (fileinfo_hash, root) = handle_images(gui)

    (fileinfo_hash, root) = handle_single(gui, fileinfo_hash, root)

    return (fileinfo_hash, root)

def handle_single(gui, fileinfo_hash, root):

    cursor = gui.case_obj.evidencedb.cursor 

    cursor.execute("select g.id, e.filename, e.file_alias from file_groups as g, evidence_sources as e where g.group_name='SINGLE' and e.id=g.partition_id")

    for (gid, evidence_file, alias) in cursor.fetchall():

        cursor.execute("select id, registry_type, md5sum, mtime from registry_files where hive_type=-1 and reg_type_id=?", [gid])
    
        for (efileid, rtype, md5sum, mtime) in cursor.fetchall():

            ename = get_ename(evidence_file, alias)
            efile = tree_entry(ename)
            root.subs.append(efile)
            efile.fileids.append(efileid)            
            root.fileids.append(efileid)

            fileinfo_hash[efileid] = rfileinfo(evidence_file, ename, evidence_file, rtype, md5sum, mtime, "SINGLE", -1, "SINGLE_TYPE") 

    return (fileinfo_hash, root)

def handle_images(gui):

    fileinfo_hash = {}

    # hash kept to make display code sane
    root = tree_entry("All Files")

    cursor = gui.case_obj.evidencedb.cursor
    cursor.execute("select filename, file_alias, id from evidence_sources")

    files  = cursor.fetchall()
    
    # for every evidence file
    for (evidence_file, alias, efileid) in files:
   
        ename = get_ename(evidence_file, alias)

        cursor.execute("select number, id from partitions where evidence_file_id=?", [efileid]) 
        partitions = cursor.fetchall()
   
        # individual registry files
        if len(partitions) == 0:
            continue

        efile = tree_entry(ename)
        root.subs.append(efile)
        
        # for each partition in the current evidence file         
        for (part_num, part_id) in partitions:

            part = tree_entry("Partition %d" % part_num)
            efile.subs.append(part)
       
            cursor.execute("select group_name, id from file_groups where partition_id=?", [part_id])
            groups = cursor.fetchall()

            # for each group in the parition 
            for (group_name, gid) in groups:

                if group_name == "SINGLE":
                    continue

                gent = tree_entry(group_name)
                part.subs.append(gent)

                cursor.execute("select type_name, id from reg_type where file_group_id=?", [gid])
                reg_types = cursor.fetchall()

                for (type_name, type_id) in reg_types:

                    tent = tree_entry(type_name)
                    gent.subs.append(tent) 

                    # check if this is an RP directory
                    cursor.execute("select rpname, id from rp_groups where reg_type_id=?", [type_id])
                    rps = cursor.fetchall()

                    tree_ents = [root, efile, part, gent, tent]

                    # this is an RP folder
                    if len(rps) > 0:
                    
                        for (rpname, rp_id) in rps: 
                            
                            rent = tree_entry(rpname)
                            tent.subs.append(rent)

                            cursor.execute("select filename, id, registry_type, md5sum, mtime from registry_files where reg_type_id=? and hive_type=1", [rp_id])

                            populate_file(evidence_file, ename, fileinfo_hash, cursor, rent, tree_ents + [rent], group_name, part_num, type_name, rpname)

                    # non-RP
                    else:
                        # get all the files from a group
                        cursor.execute("select filename, id, registry_type, md5sum, mtime from registry_files where reg_type_id=? and hive_type=0", [type_id])

                        populate_file(evidence_file, ename, fileinfo_hash, cursor, tent, tree_ents, group_name, part_num, type_name)

    return (fileinfo_hash, root)

def populate_file(evidence_file, ename, fileinfo_hash, cursor, ent, tree_ents, group_name, part_num, type_name, rpname=""):
 
    regfiles = cursor.fetchall()

    for (rfile, fileid, rtype, md5sum, mtime) in regfiles:
        
        fent = tree_entry(rfile)
        ent.subs.append(fent)

        fileinfo_hash[fileid] = rfileinfo(evidence_file, ename, rfile, rtype, md5sum, mtime, group_name, part_num, type_name, rpname) 

        for ent in tree_ents:
            ent.fileids.append(fileid)

        fent.fileids.append(fileid)

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

def get_tree_node(self, userpath=""):

    ret = None

    if userpath:
        path = userpath
        ok   = True
    else:
        (path, ok) = QInputDialog.getText(self.gui, "Please Enter the Registry Path", "Path:")

    if ok and (userpath or not path.isEmpty()):
        # try to help out the user 
        
        # if they didn't give leading \, add it
        if path[0] != "\\":
            path = "\\" + path

        # if they gave a trailing \, strip it
        if path[-1] == "\\":
            path = path[:-1]

        fullpath = unicode(self.tapi.get_path(path))

        ret = get_path_node(self, fullpath)

    return ret

def get_path_node(self, path):
        
    nodes = self.tapi.root_path_node(path)     

    if nodes:
        node = nodes[-1]
    else:
        return None 

    return node

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

def get_file_info(fhash, fileid, extra=0):

    finfo = fhash[fileid]

    filepath   = finfo.reg_file
    regfile   = finfo.reg_file
    alias      = finfo.alias
    evi_file   = finfo.evidence_file
    group_name = finfo.group_name
    part_num   = finfo.part_num
    type_name  = finfo.type_name
    rpname     = finfo.rp_name    


    if group_name != "SINGLE":

        group_info = "Partition %s | %s | %s" % (part_num, group_name, type_name) 
       
        if rpname:
            group_info = group_info + " | " + rpname

        filepath = "%s in %s from %s" % (filepath, group_info, evi_file)

    else:
        group_info = group_name

    # if an alias was given
    if len(alias) and evi_file != alias:
        filepath = filepath + " ( %s )" % alias
    
    if extra:
        ret = (evi_file, group_info, alias, regfile)
    else:
        ret = (filepath, evi_file, group_name)

    return ret

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

# used to get the search/path term or terms from a file for the search and paths tab
def get_search_terms(gui, place="search"):    

    edit = gui.__getattribute__("%sLineEdit" % place)
    searchterm = unicode(edit.text())

    # the user entered a single search term
    if len(searchterm) > 0:
        searchterms = [searchterm]
        filename    = ""

    else:
        searchterms = []

        lineedit =  gui.__getattribute__("%sTermsLineEdit" % place)
        filename = unicode(lineedit.text())

        try:
            fd = open(filename, "rb")
        except:
            gui.msgBox("Unable to open given search terms file. Cannot Proceed")
            return (searchterms, "")

        for term in fd.readlines():

            # carefully remove newlines from terms...
            if term[-1] == '\n':
                term = term[:-1]

            if term[-1] == '\r':
                term = term[:-1]

            searchterms.append(term)                

    return (searchterms, filename)



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
 
    def get_current_row_node(self):
        
        curtab = self.ref_obj.gui.analysisTabWidget.currentWidget()
        
        self.ref_obj.gui.case_obj.current_fileid = curtab.fileid

        table      = curtab.searchResTable

        row        = table.currentRow()

        # get the key column no matter which the user picked
        item       = table.item(row, 1)

        fullpath   = unicode(item.text())

        node = self.ref_obj.tapi.root_path_node(fullpath)[-1]

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
            node = self.ref_obj.tapi.idxtonode(ent.nid)

            if node.nodeid == target_node.nodeid:
                ret = p
                break

        return ret

 

