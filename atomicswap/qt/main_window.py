# Copyright (c) 2019-2020 The atomicswap-qt developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from PyQt5.QtWidgets import (QMainWindow, QDesktopWidget, QWidget, QAction, QMenuBar, qApp, QApplication, QLabel, QMenu,
                             QDialog, QTabWidget, QVBoxLayout, QTreeView, QAbstractItemView, QHeaderView, QMessageBox)
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtGui import QStandardItemModel, QPixmap

from enum import IntEnum

from atomicswap.transaction import MsgTx
from atomicswap.util import History_DB, resource_path, status_icons
from atomicswap.version import full_version

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = "atomicswap-qt"
        self.left = 0
        self.top = 0
        self.width = 800
        self.height = 500
        self.history_db = History_DB()
        self.main_window = QWidget(self)
        self.main_vbox = QVBoxLayout(self.main_window)
        self.init_menubar()

        # make tabs
        self.tabs = QTabWidget()
        self.history_tab = QWidget()
        self.history_vbox = QVBoxLayout(self.history_tab)
        self.history_view = HistoryView(self)
        self.history_vbox.addWidget(self.history_view)
        # self.command_tab = QWidget()

        # Add tabs
        self.tabs.addTab(self.history_tab, "History")
        # self.tabs.addTab(self.command_tab, "Commands")

        self.main_vbox.addWidget(self.tabs)

        self.setCentralWidget(self.main_window)
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.center()

        self.statusBar()
        self.setCentralWidget(self.main_window)
        self.show()

    def init_menubar(self):
        menubar = QMenuBar()

        # File menu
        file_menu = menubar.addMenu("&File")
        exit_action = QAction('&Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.setStatusTip('Exit application')
        exit_action.triggered.connect(qApp.quit)
        atomicswap_action = QAction('&New AtomicSwap', self)
        atomicswap_action.setShortcut('Ctrl+A')
        atomicswap_action.setStatusTip('Start new atomic swap contract')
        atomicswap_action.triggered.connect(self.atomicswap_window)
        file_menu.addAction(atomicswap_action)
        file_menu.addSeparator()
        file_menu.addAction(exit_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")
        about_atomicswap_qt_action = QAction('About atomicswap-qt', self)
        about_atomicswap_qt_action.setStatusTip('About atomicswap-qt')
        about_atomicswap_qt_action.triggered.connect(self.about_dialog)
        about_qt_action = QAction('About Qt', self)
        about_qt_action.setStatusTip('About Qt')
        about_qt_action.triggered.connect(QApplication.aboutQt)
        help_menu.addAction(about_atomicswap_qt_action)
        help_menu.addAction(about_qt_action)

        self.setMenuBar(menubar)

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def atomicswap_window(self):
        from .atomicswap_window import AtomicSwapWindow
        asw = AtomicSwapWindow(self)
        asw.show()

    def resume_atomicswap(self, data: dict, refund=False):
        from .atomicswap_window import AtomicSwapWindow
        asw = AtomicSwapWindow(self)
        try:
            error = asw.resume_atomicswap(data)
        except:
            error = "Fatal problem has occurred!"
        if error:
            QMessageBox.critical(self, 'Error', error, QMessageBox.Ok, QMessageBox.Ok)
            return None
        if refund:
            return asw
        else:
            print(4)
            asw.show()
            return None

    def refund_atomicswap(self, data: dict):
        asw = self.resume_atomicswap(data, True)
        if not asw:
            return
        refund_tx = asw.send_contract_tuple.refund_tx
        assert isinstance(refund_tx, MsgTx)
        send_question = QMessageBox.question(self, 'Question',
                                             f"Send transaction? ({refund_tx.get_txid().hex()})",
                                             QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if send_question == QMessageBox.No:
            return
        try:
            result = asw.receive_coind.sendrawtransaction(refund_tx.serialize_witness().hex())
            assert result == refund_tx.get_txid().hex()
        except:
            QMessageBox.warning(self, 'Failed', 'Transaction broadcast was fail.', QMessageBox.Ok, QMessageBox.Ok)
            return
        QMessageBox.information(self, 'Succeed', 'Transaction was broadcast', QMessageBox.Ok, QMessageBox.Ok)
        return

    def details_dialog(self, data: dict):
        from .details_dialog import DetailsDialog
        dd = DetailsDialog(self, data)
        dd.exec_()

    def about_dialog(self):
        QMessageBox.about(self,
                          "About atomicswap-qt - atomicswap-qt",
                          f'<u><i><h1>atomicswap-qt Version {full_version}</h1></i></u>' + '<br />' +
                          'Copyright(c) 2011-2020 The Electrum Developers' + '<br />' +
                          'Copyright(c) 2013-2020 The btcsuite developers' + '<br />' +
                          'Copyright(c) 2015-2020 The Decred developers' + '<br />' +
                          'Copyright(c) 2019-2020 The atomicswap-qt developers' + '<br /><br />' +
                          'This software is rewrite ' +
                          '<a href="https://github.com/decred/atomicswap">decred/atomicswap</a> ' +
                          'by Python3 and add GUI by PyQt5.' + '<br /><br />' +
                          '<b>This software point</b>' + '<br />' +
                          '* ' + 'Full scratch base function' + '<br />' +
                          '* ' + 'Only used standard library, pyqt5, requests and pyperclip.' + '<br />' +
                          '* ' + 'Can use on the gui' + '<br />' +
                          '* ' + 'Full compatible with decred/atomicswap' + '<br /><br />' +
                          'This software is ' +
                          '<a href="https://github.com/y-chan/atomicswap-qt/blob/master/LICENSE">' +
                          'MIT License</a>.' + ' ' + 'And ' + '<a href="https://github.com/y-chan/atomicswap-qt">' +
                          'OSS</a>.')

class HistoryView(QTreeView):

    class Columns(IntEnum):
        STATUS = 0
        SEND_COIN = 1
        SEND_VALUE = 2
        RECEIVE_COIN = 3
        RECEIVE_VALUE = 4
        SECRET_HASH = 5

    def __init__(self, parent: MainWindow):
        super().__init__()
        self.parent = parent
        self.setItemsExpandable(False)
        self.setIndentation(0)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.create_menu)
        self.set_model()
        self.header().setResizeContentsPrecision(0)
        self.header().setStretchLastSection(False)
        self.header().setSectionResizeMode(1, QHeaderView.Stretch)
        self.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self.update()

    def selected_in_column(self, column: int):
        items = self.selectionModel().selectedIndexes()
        return list(x for x in items if x.column() == column)

    def update(self):
        self.set_model()
        for i, key in enumerate(self.parent.history_db.keys()):
            data = self.parent.history_db.get_data(key)
            self.model().insertRow(i)
            # self.model().setData(self.model().index(0, self.Columns.STATUS), data["Status"])
            self.model().setData(self.model().index(i, self.Columns.SEND_COIN), data["Send"]["Coin"])
            self.model().setData(self.model().index(i, self.Columns.SEND_VALUE), data["Send"]["Value"])
            self.model().setData(self.model().index(i, self.Columns.RECEIVE_COIN), data["Receive"]["Coin"])
            self.model().setData(self.model().index(i, self.Columns.RECEIVE_VALUE), data["Receive"]["Value"])
            self.model().setData(self.model().index(i, self.Columns.SECRET_HASH), data["SecretHash"])
            status_label = QLabel()
            icon = QPixmap(resource_path('qt', 'icons', status_icons[data["Status"]])).scaled(15, 15)
            status_label.setPixmap(icon)
            index = self.model().index(i, 0, QModelIndex())
            self.setIndexWidget(index, status_label)

    def set_model(self):
        self.setModel(QStandardItemModel(0, 6, self))
        self.model().setHeaderData(self.Columns.STATUS, Qt.Horizontal, "Status")
        self.model().setHeaderData(self.Columns.SEND_COIN, Qt.Horizontal, "Send Coin")
        self.model().setHeaderData(self.Columns.SEND_VALUE, Qt.Horizontal, "Send Value")
        self.model().setHeaderData(self.Columns.RECEIVE_COIN, Qt.Horizontal, "Receive Coin")
        self.model().setHeaderData(self.Columns.RECEIVE_VALUE, Qt.Horizontal, "Receive Value")
        self.model().setHeaderData(self.Columns.SECRET_HASH, Qt.Horizontal, "Secret Hash")

    def mouseDoubleClickEvent(self, item):
        idx = self.indexAt(item.pos())
        if not idx.isValid():
            return
        key = self.model().itemFromIndex(self.selected_in_column(self.Columns.SECRET_HASH)[0]).text()
        data = self.parent.history_db.get_data(key)
        self.parent.details_dialog(data)

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selected_in_column(1)
        multi_select = len(selected) > 1
        if not selected:
            menu.addAction("New AtomicSwap", self.parent.atomicswap_window)
        elif not multi_select:
            key = self.model().itemFromIndex(self.selected_in_column(self.Columns.SECRET_HASH)[0]).text()
            data = self.parent.history_db.get_data(key)
            if data["Status"] == 0 or data["Status"] == 2:
                menu.addAction("Resume atomicswap", lambda: self.parent.resume_atomicswap(data))
            if data["Status"] == 2:
                menu.addAction("Refund atomicswap", lambda: self.parent.refund_atomicswap(data))
            menu.addAction("Details atomicswap", lambda: self.parent.details_dialog(data))
            menu.addAction("Delete atomicswap history", lambda: self.delete_atomicswap_history(data))
        menu.exec_(self.viewport().mapToGlobal(position))

    def delete_atomicswap_history(self, data: dict):
        send_coin = data["Send"]["Coin"]
        receive_coin = data["Receive"]["Coin"]
        delete_question = QMessageBox.warning(self, 'Warning',
                                              f"Delete {send_coin} to {receive_coin} atomicswap history?",
                                              QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if delete_question == QMessageBox.No:
            return
        self.parent.history_db.delete_data(data["SecretHash"])
        self.update()
