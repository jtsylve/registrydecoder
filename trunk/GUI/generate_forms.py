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

import random

import guicommon

class generate_forms:

    def __init__(self, gui):
        self.gui = gui

    # set a random name for one of the randomly generated objects
    # the objects will never be referenced by name
    def setObjectName(self, obj, name):

        extra = "%d%d" % (random.randint(5, 45000), random.randint(50000, 256000000))
        name = name + extra

        obj.setObjectName(name)

    def generate_search_view_form(self, ref_obj, fileid, tab_name, label_text, results): 
        return self.search_plugin_export_form(ref_obj, fileid, tab_name, label_text, results)

    def plugin_export_form(self, ref_obj, fileid, tab_name, label_text): 
        return self.search_plugin_export_form(ref_obj, fileid, tab_name, label_text)

    def path_export_form(self, ref_obj, fileid, tab_name, label_text):
        return self.search_plugin_export_form(ref_obj, fileid, tab_name, label_text)        

    # this is pretty ugly, a mix up of a few functions, has cruft everywhere, etc
    def search_plugin_export_form(self, ref_obj, fileid, tab_name, label_text, results=None):

        pluginTab = QWidget()
        searchTab = pluginTab
        tab       = pluginTab
        new_tab   = pluginTab

        self.setObjectName(pluginTab, "pluginTab")
        searchGrid   = QGridLayout(pluginTab)
        gridLayout_9 = searchGrid
        self.setObjectName(searchGrid, "searchGrid")

        # search results label
        label_12 = QLabel(searchTab)
        self.setObjectName(label_12, "label_12")
        
        label_12.setText(QString(label_text))
        
        gridLayout_9.addWidget(label_12, 0, 0, 1, 1)

        tableWidget = QTableWidget(tab)
        self.setObjectName(tableWidget, "taableWidget")
        tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers);

        gridLayout_9.addWidget(tableWidget, 1, 0, 1, 1)

        gridLayout_8 = QGridLayout()
        self.setObjectName(gridLayout_8, "gridLayout_8")

        label_13 = QLabel(tab)
        label_13.setObjectName("label_13")
        gridLayout_8.addWidget(label_13, 0, 0, 1, 1)

        label_14 = QLabel(tab)
        self.setObjectName(label_14, "label_14")
        gridLayout_8.addWidget(label_14, 0, 1, 1, 1)

        searchReportComboBox = QComboBox(tab)
        self.setObjectName(searchReportComboBox, "ssearchReportComboBox")
        gridLayout_8.addWidget(searchReportComboBox, 1, 0, 1, 1)

        SearchReportFilenameLineEdit = QLineEdit(tab)
        self.setObjectName(SearchReportFilenameLineEdit, "SearchReportFilenameLineEdit")
        gridLayout_8.addWidget(SearchReportFilenameLineEdit, 1, 1, 1, 1)

        createReportPushButton = QPushButton(tab)
        self.setObjectName(createReportPushButton, "createReportPushButton")

        gridLayout_8.addWidget(createReportPushButton, 1, 2, 1, 1)
        gridLayout_9.addLayout(gridLayout_8, 2, 0, 1, 1)

        label_13.setText("Report Format")
        label_14.setText("Report Filename")

        createReportPushButton.setText("Create Report")
     
        # register signals
        ref_obj.gui.connect(createReportPushButton, SIGNAL("clicked()"), ref_obj.createReportClicked)  
        SearchReportFilenameLineEdit.mousePressEvent =  ref_obj.gui.get_report_name

        self.set_ctrlw_handler(ref_obj.gui, new_tab)

        for report in ref_obj.rm.file_reports:
            searchReportComboBox.addItem(QString(report.name))

        ref_obj.gui.analysisTabWidget.addTab(new_tab, QString(tab_name))

        tableWidget.setSortingEnabled(True)

        # this is sent by search tabs
        if results:
            tableWidget.setColumnCount(3)
            tableWidget.setRowCount(len(results))
            tableWidget.keyPressEvent = ref_obj.handle_search_delete

        new_tab.searchResTable = tableWidget
        new_tab.searchResLabel = label_12

        # keep references to the table and the combobox
        new_tab.tblWidget    = tableWidget
        new_tab.cbox         = searchReportComboBox
        new_tab.fileid       = fileid
        new_tab.reportname   = SearchReportFilenameLineEdit
        
        new_tab.messageLabel = label_12
        new_tab.pushbutton   = createReportPushButton
        new_tab.label1       = label_13
        new_tab.label2       = label_14

        return new_tab
    
    def set_ctrlw_handler(self, gui, new_tab):

        actt = QAction(gui)
        actt.setAutoRepeat(False)
        actt.setShortcut("Ctrl+W")
        
        gui.connect(actt, SIGNAL("triggered()"), gui.ctrlw_tab)
        
        new_tab.addAction(actt)

    # form used to export all searches/plugins/etc
    def export_all_form(self, ref_obj, tab_name):

        # the tab itself
        exportTab = QWidget()
        self.setObjectName(exportTab, "exportTab")

        # outer grid
        gridLayout_outer = QGridLayout(exportTab)
        self.setObjectName(gridLayout_outer, "gridLayout_outer")
        spacerItem = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        spacerItem1 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        gridLayout_outer.addItem(spacerItem, 0, 0, 1, 1)
        gridLayout_outer.addItem(spacerItem1, 0, 3, 1, 1)
    
        # outer layout
        exportTabBigLayout = QGridLayout()
        self.setObjectName(exportTabBigLayout, "exportTabBigLayout")
        
        # file label
        exportFileLabel = QLabel(exportTab)
        exportFileLabel.setAlignment(Qt.AlignCenter)
        self.setObjectName(exportFileLabel, "exportFileLabel")
        exportTabBigLayout.addWidget(exportFileLabel, 4, 1, 1, 1)
        exportFileLabel.setText(QApplication.translate("registrydecoder", "Report File", None, QApplication.UnicodeUTF8))
    
        # line edit
        bulkExportLineEdit = QLineEdit(exportTab)
        self.setObjectName(bulkExportLineEdit, "bulkExportLineEdit")
        exportTabBigLayout.addWidget(bulkExportLineEdit, 5, 0, 1, 3)
    
        # export label
        bulkExportFormatLabel = QLabel(exportTab)
        bulkExportFormatLabel.setAlignment(Qt.AlignBottom|Qt.AlignHCenter)
        bulkExportFormatLabel.setObjectName("bulkExportFormatLabel")
        bulkExportFormatLabel.setText(QApplication.translate("registrydecoder", "Export Format", None, QApplication.UnicodeUTF8))
        exportTabBigLayout.addWidget(bulkExportFormatLabel, 7, 1, 1, 1)

        # export combo
        bulkExportComboBox = QComboBox(exportTab)
        bulkExportComboBox.setObjectName("bulkExportComboBOx")
        exportTabBigLayout.addWidget(bulkExportComboBox, 8, 0, 1, 3)
    
        # info label
        exportInfoLabel = QLabel(exportTab)
        exportInfoLabel.setText("")
        exportInfoLabel.setAlignment(Qt.AlignCenter)
        self.setObjectName(exportInfoLabel, "exportInfoLabel")
        exportTabBigLayout.addWidget(exportInfoLabel, 1, 0, 2, 3)
    
        spacerItem2 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        exportTabBigLayout.addItem(spacerItem2, 14, 0, 1, 3)    
        spacerItem3 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        exportTabBigLayout.addItem(spacerItem3, 12, 0, 1, 3)
        spacerItem4 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        exportTabBigLayout.addItem(spacerItem4, 6, 0, 1, 3)
        spacerItem5 = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        exportTabBigLayout.addItem(spacerItem5, 11, 0, 1, 1)
        
        # export push button
        bulkExportPushButton = QPushButton(exportTab)
        self.setObjectName(bulkExportPushButton, "bulkExportPushButton")
        bulkExportPushButton.setText(QApplication.translate("registrydecoder", "Export All", None, QApplication.UnicodeUTF8))

        exportTabBigLayout.addWidget(bulkExportPushButton, 10, 1, 1, 1)
        
        spacerItem6 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        exportTabBigLayout.addItem(spacerItem6, 10, 0, 1, 1)
        spacerItem7 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        exportTabBigLayout.addItem(spacerItem7, 10, 2, 1, 1)
        spacerItem8 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        exportTabBigLayout.addItem(spacerItem8, 3, 0, 1, 3)
        spacerItem9 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        exportTabBigLayout.addItem(spacerItem9, 9, 0, 1, 3)
        
        gridLayout_outer.addLayout(exportTabBigLayout, 0, 1, 1, 1)
        
        # add with proper name
        self.gui.analysisTabWidget.addTab(exportTab, QString(tab_name))
    
        self.set_ctrlw_handler(self.gui, exportTab)
 
        for report in ref_obj.rm.file_reports:
            bulkExportComboBox.addItem(QString(report.name))

        # signals
        self.gui.connect(bulkExportPushButton, SIGNAL("clicked()"), ref_obj.exportAll)   
        bulkExportLineEdit.mousePressEvent =  self.gui.get_report_name
        
        # keep references
        exportTab.button       = bulkExportPushButton
        exportTab.reportname   = bulkExportLineEdit
        exportTab.cbox         = bulkExportComboBox
        
        exportTab.is_bulk      = 1

        return exportTab

    # gets hive view portion of File View auto tab
    def generate_file_view_form(self, ref_obj, fileid, gui, filepath):      
    
        fileViewTab = QWidget()
        self.setObjectName(fileViewTab, "fileViewTab")
       
        fileViewLayout = QGridLayout(fileViewTab)
        self.setObjectName(fileViewLayout, "fileViewLayout")
        
        model = ref_obj.model_ref(fileViewTab, ref_obj, gui, fileid, filepath)  

        ViewFileTreeWidget = QTreeView(fileViewTab)
        ViewFileTreeWidget.setModel(model)

        self.setObjectName(ViewFileTreeWidget, "ViewFileTreeWidget")

        fileViewLayout.addWidget(ViewFileTreeWidget, 0, 0, 2, 1)
       
        ViewDataTableWidget = QTableWidget(fileViewTab)
        self.setObjectName(ViewDataTableWidget, "ViewDataTableWidget")
        ViewDataTableWidget.setColumnCount(3)
        ViewDataTableWidget.setRowCount(0)
        item = QTableWidgetItem()
        ViewDataTableWidget.setHorizontalHeaderItem(0, item)
        item = QTableWidgetItem()
        ViewDataTableWidget.setHorizontalHeaderItem(1, item)
        item = QTableWidgetItem()
        ViewDataTableWidget.setHorizontalHeaderItem(2, item) 
        ViewDataTableWidget.horizontalHeaderItem(0).setText(QString("Name"))
        ViewDataTableWidget.horizontalHeaderItem(1).setText(QString("Type"))
        ViewDataTableWidget.horizontalHeaderItem(2).setText(QString("Data"))
        ViewDataTableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers);
        ViewDataTableWidget.setSortingEnabled(True)


        fileViewLayout.addWidget(ViewDataTableWidget, 0, 1, 1, 1)
       
        hexDumpTable = QTableWidget(fileViewTab)
        hexDumpTable.setEditTriggers(QAbstractItemView.NoEditTriggers);
        self.setObjectName(hexDumpTable, "hexDumpTable")
        fileViewLayout.addWidget(hexDumpTable, 1, 1, 2, 1)
        
        currentFilePathLineEdit = QLineEdit(fileViewTab)
        currentFilePathLineEdit.setReadOnly(True)
        self.setObjectName(currentFilePathLineEdit, "currentFilePathLineEdit")
        
        fileViewLayout.addWidget(currentFilePathLineEdit, 2, 0, 1, 1)
        
        self.gui.analysisTabWidget.addTab(fileViewTab, QString("Browse"))

        # set the file id for the form
        fileViewTab.fileid = fileid

        # save the form widget refs
        fileViewTab.viewTree    = ViewFileTreeWidget
        fileViewTab.hexDump     = hexDumpTable
        fileViewTab.valueTable  = ViewDataTableWidget
        fileViewTab.currentPath = currentFilePathLineEdit

        fileViewTab.valueTable.setHorizontalHeaderLabels(("Name", "Type", "Data"))
        fileViewTab.valueTable.setColumnCount(3)        
        fileViewTab.valueTable.setShowGrid(False)

        self.gui.connect(fileViewTab.viewTree,   SIGNAL("clicked(QModelIndex)"), model.key_clicked)
        self.gui.connect(fileViewTab.valueTable, SIGNAL("cellPressed(int,int)"), model.val_clicked)
        
        self.gui.connect(ViewFileTreeWidget.selectionModel(), SIGNAL("selectionChanged(QItemSelection, QItemSelection)"), model.arrow_move)
        self.gui.connect(ViewDataTableWidget.selectionModel(), SIGNAL("selectionChanged(QItemSelection, QItemSelection)"), model.value_arrow_move)

        self.set_ctrlw_handler(self.gui, fileViewTab)
        
        return fileViewTab 
 


