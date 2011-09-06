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
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

import sys
import datetime
import binascii

rolenum = 32

RegTypes = {
    0 : "REG_NONE",
    1 : "REG_SZ",
    2 : "REG_EXPAND_SZ",
    3 : "REG_BINARY",
    4 : "REG_DWORD",
    5 : "REG_DWORD_BIG_ENDIAN",
    6 : "REG_LINK",
    7 : "REG_MULTI_SZ",
    8 : "REG_RESOURCE_LIST",
    9 : "REG_FULL_RESOURCE_DESCRIPTOR",
    10 : "REG_RESOURCE_REQUIREMENTS_LIST",
    11 : "REG_QWORD",
    12 : "UNKNOWN_TYPE" }

# each entry in the hive 
class treeEnt:

    def __init__(self, parent, nodeid, row, column):

        self.parent = parent
        self.nid    = nodeid
        self.row    = row
        self.column = column

class hexval:

    def __init__(self, name, rtype, val, raw):

        self.name  = name
        self.rtype = rtype
        self.val   = val
        self.raw   = raw

# implements the hive tree view
class hiveTreeModel(QAbstractItemModel):

    def __init__(self, fileViewTab, ref_obj, gui, fileid, filepath, parent=None):

        QAbstractItemModel.__init__(self, parent)

        self.filetab  = fileViewTab
        self.ftabinst = ref_obj
        self.tapi     = ref_obj.tapi
        self.gui     = gui
        self.fileid  = fileid

        self.nodehash = {}
        self.ents = {}
        self.idxs = {}

        # used to track for the hexdump
        self.vals = {}

        self.filepath = filepath
    
    def set_fid(self):    
        self.gui.case_obj.current_fileid = self.fileid

    def data(self, index, role):

        ret = QVariant()

        if index.isValid() and role == Qt.DisplayRole:
        
            ent = index.internalPointer()
            node = self.tapi.idxtonode(ent.nid)
            name = self.tapi.key_name(node)
            
            ret = QVariant(name)
        
        elif index.isValid() and role == Qt.ForegroundRole:

            color = QColor(Qt.blue)
            return QVariant(color)

        return ret

    def columnCount(self, parent):
        return 1

    def rowCount(self, parent):

        self.set_fid()

        if parent.column() > 0:
            return 0

        if not parent.isValid():
            node = self.tapi.root_node()
        else:
            i = parent.internalPointer()
            pid = i.nid
            node = self.tapi.idxtonode(pid)

        if node in self.nodehash:
            ret = len(self.nodehash[node])
        else:
            children = self.get_ordered_children(node)

            self.nodehash[node] = children
        
            ret = len(children)
 
        return ret
        
    def headerData(self, section, ort, role):
        
        if ort == Qt.Horizontal and role == Qt.DisplayRole and section == 0:
            ret = QVariant(self.filepath)
        else:
            ret = QVariant()

        return ret
            
    def index(self, row, column, parent):

        self.set_fid()

        ret = QModelIndex()

        if self.hasIndex(row, column, parent):

            if not parent.isValid():
                node = self.tapi.root_node()
                nid  = node.nodeid
            else:
                nid  = parent.internalPointer().nid
                node = self.tapi.idxtonode(nid)
            
            if not node in self.nodehash:
                children = self.get_ordered_children(node)
                self.nodehash[node] = children

            # list of ordered children keys
            child = self.nodehash[node][row]

            if child.nodeid in self.ents:
                ret = self.idxs[child.nodeid]                
            else:
                e = treeEnt(node, child.nodeid, row, column)
                ret = self.createIndex(row, column, e)
                self.ents[child.nodeid] = e
                self.idxs[child.nodeid] = ret
            
        return ret

    def get_ordered_children(self, node):

        children = {}
        ret = []
       
        node_list = self.tapi.get_children_fid(node, 1)

        # walk each child, get name and node
        for nid in node_list:

            child_list = node_list[nid]

            for child in child_list:
                cname = self.tapi.key_name(child)

                children[cname] = child
            
        keys = sorted(children.keys())

        # fill return list with the nodes in order
        for cname in keys:
            ret.append(children[cname])

        return ret    

    def parent(self, index):

        self.set_fid()

        ret = QModelIndex()

        if index.isValid():
        
            ent = index.internalPointer()
 
            parent = ent.parent
            
            if parent == self.tapi.root_node():
                return ret

            if parent.nodeid in self.ents:
                row = self.ents[parent.nodeid].row

            e = self.ents[parent.nodeid]
            ret = self.createIndex(row, 0, e)
                
        return ret
   
    def value_arrow_move(self, idxs, unused):

        idxs = idxs.indexes()

        if len(idxs) > 0:
            
            index = idxs[0]
        
            self.val_clicked(index.row(), index.column())

 
    def arrow_move(self, idxs, unused):

        idxs = idxs.indexes()

        # not sure what to do if user selects more than one key, just show first
        if len(idxs) > 0:
        
            index = idxs[0]

            self.key_clicked(index)
        
    '''
    When a key is clicked in the hive view
    We need to:
    1) List the name/data/value in the right panel
    2) List fullpath and last written time in bottom input box
    '''
    def key_clicked(self, index):
        
        ent = index.internalPointer()

        node = self.tapi.idxtonode(ent.nid)

        self.place_last_written(node)

        # clear the hex dump table on each click, will get refilled with list_values
        self.filetab.hexDump.clear()

        self.list_values(node)
    
    def place_last_written(self, node):
        
        path = self.tapi.full_path_node_to_root(node)

        lastwrite = node.timestamps[self.fileid]
        lastwrite = datetime.datetime.fromtimestamp(lastwrite).strftime('%Y/%m/%d %H:%M:%S UTC')

        self.filetab.currentPath.clear()
        self.filetab.currentPath.insert(path + " -- " + lastwrite)

    def list_values(self, node):

        row = 0
        
        vals = self.tapi.values_for_node(node)
        
        self.filetab.valueTable.setRowCount(len(vals))

        for nodeval in vals:
           
            name  = self.tapi.stringid(nodeval.namesid)
            val   = self.tapi.stringid(nodeval.asciisid)
            raw   = self.tapi.stringid(nodeval.rawsid)  #self.tapi.reg_get_raw_value_data(nodeval)#self.tapi.stringid(nodeval.rawsid)
            rtype = RegTypes[int(nodeval.regtype)]
            
            if raw and rtype == "REG_BINARY":
                raw = binascii.unhexlify(raw)
            else:
                raw = val

            nvals = [name, rtype, val]
            col  = 0

            self.vals[row] = hexval(name, rtype, val, raw) 

            # write them into the table
            for v in nvals: 
                item =  QTableWidgetItem(QString(v))
                self.filetab.valueTable.setItem(row, col, item)        
                col = col + 1

            row = row + 1
        
        self.filetab.valueTable.resizeColumnsToContents()

    # when a value entry is clicked
    def val_clicked(self, row, column): 

        if row in self.vals:
        
            self.filetab.hexDump.clear()
            vals = self.vals[row]
            self.hexdump(vals.raw)

    def add_val(self, string, row, col):

        item = QTableWidgetItem(QString(string))
        self.filetab.hexDump.setItem(row, col, item)        

    def hexdump(self, buf):

        width = 16
        blen  = len(buf)
        row   = 0
        tbl = self.filetab.hexDump

        numrows = blen / width
        if blen % width != 0:
            numrows = numrows + 1

        tbl.setColumnCount(width+2)
        tbl.setRowCount(numrows)
       
        # no headers
        tbl.setShowGrid(False)        
        tbl.horizontalHeader().hide()
        tbl.verticalHeader().hide()

        for offset in xrange(0, blen, width):

            self.add_val("%d" % offset, row, 0)

            cur = buf[offset:offset+width]

            for col in xrange(0, width):
            
                # add the hex values offset by one for hexdump offset
                try:
                    c = cur[col]
                except:
                    break
                
                self.add_val("%.02x" % ord(c), row, col+1) 
            
            dots = ''.join( ['.', c][c.isalnum()] for c in cur )

            self.add_val(dots, row, width+1)

            row = row + 1

        tbl.resizeColumnsToContents()

class filetab:

    def __init__(self, gui):
        self.name = "File View Tab"
        self.active_tabs = {}

        self.gui = gui

        self.model_ref = hiveTreeModel

    # draw the inital page with all the registry hives for the case
    def draw(self):
        self.fileinfo_hash = self.gcommon.fill_tree(self.gui, "fileTreeWidget")     
    
    # called when 'view' is clicked on file tab
    def viewTree(self, fileids=[]):
        
        if not fileids:
            fileids = self.gcommon.get_reg_fileids(self, "fileTreeWidget") 
            # user did not select a file
            if not fileids:
                return


        for fileid in fileids:
            filepath = self.fileinfo_hash[fileid].reg_file

            tab = self.gf.generate_file_view_form(self, fileid, self.gui, filepath)

            self.active_tabs[tab] = fileid

        # to ensure other does not grab the stale fileid
        self.gui.case_obj.current_fileid = -42
 
        return tab
 
