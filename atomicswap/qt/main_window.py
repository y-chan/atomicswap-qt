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

from PyQt5.QtWidgets import (QMainWindow, QDesktopWidget, QWidget, QAction, QMenuBar, qApp, QStackedWidget, QTextEdit,
                             QApplication, QLabel, QMenu, QTabWidget, QVBoxLayout, QHBoxLayout, QPushButton, QGroupBox,
                             QTreeView, QAbstractItemView, QHeaderView, QMessageBox, QComboBox, QLineEdit)
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtGui import QStandardItemModel, QPixmap

from enum import IntEnum

from atomicswap.auditcontract import auditcontract_print
from atomicswap.initiate import initiate, initiate_print
from atomicswap.participate import participate, participate_print
from atomicswap.extractsecret import extractsecret, extractsecret_print
from atomicswap.redeem import redeem, redeem_print
from atomicswap.refund import refund, refund_print

from atomicswap.coind import make_coin_data, InvalidRPCError, GetConfigError, RestartWallet
from atomicswap.contract import built_tuple
from atomicswap.transaction import MsgTx
from atomicswap.util import HistoryDB, resource_path, status_icons, coin_list, command_list, to_satoshis
from atomicswap.version import full_version

import atomicswap


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = "atomicswap-qt"
        self.left = 0
        self.top = 0
        self.width = 800
        self.height = 500
        self.coind = None
        self.history_db = HistoryDB()
        self.initiate_result = None
        self.participate_result = None
        self.redeem_result = None
        self.refund_result = None
        self.main_window = QWidget(self)
        self.main_vbox = QVBoxLayout(self.main_window)
        self.init_menubar()

        # make history tab
        self.history_tab = QWidget()
        self.history_vbox = QVBoxLayout(self.history_tab)
        self.history_view = HistoryView(self)
        self.history_vbox.addWidget(self.history_view)

        # make command tab
        self.command_tab = QWidget()
        self.command_vbox = QVBoxLayout(self.command_tab)
        self.coin_hbox = QHBoxLayout()
        self.coin_label = QLabel("Select coin")
        self.coind_check_label = QLabel("Coind isn't OK")
        self.coin_hbox.addWidget(self.coin_label)
        self.coin_hbox.addStretch(1)
        self.coin_hbox.addWidget(self.coind_check_label)
        self.coin_combo = QComboBox(self)
        self.coin_combo.addItems(coin_list)
        self.coin_combo.activated[str].connect(self.coind_check)
        self.command_label = QLabel("Select command")
        self.command_combo = QComboBox(self)
        self.command_combo.addItems(command_list)
        self.command_combo.activated[str].connect(self.command_update)
        self.clear_hbox = QHBoxLayout()
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_box)
        self.clear_hbox.addStretch(1)
        self.clear_hbox.addWidget(self.clear_button)
        self.command_widget = QStackedWidget()
        # initiate
        self.initiate_widget = QWidget()
        self.initiate_vbox = QVBoxLayout(self.initiate_widget)
        self.initiate_hbox = QHBoxLayout()
        self.initiate_addr_label = QLabel("Address")
        self.initiate_addr = QLineEdit(self)
        self.initiate_amount_label = QLabel("Amount")
        self.initiate_amount = QLineEdit(self)
        self.initiate_execute = QPushButton("Execute")
        self.initiate_execute.clicked.connect(self.clicked)
        self.initiate_publish = QPushButton("Publish Tx")
        self.initiate_publish.clicked.connect(self.publish_tx)
        self.initiate_publish.setDisabled(True)
        self.initiate_hbox.addStretch(1)
        self.initiate_hbox.addWidget(self.initiate_execute)
        self.initiate_hbox.addWidget(self.initiate_publish)
        self.initiate_vbox.addWidget(self.initiate_addr_label)
        self.initiate_vbox.addWidget(self.initiate_addr)
        self.initiate_vbox.addWidget(self.initiate_amount_label)
        self.initiate_vbox.addWidget(self.initiate_amount)
        self.initiate_vbox.addLayout(self.initiate_hbox)
        # participate
        self.participate_widget = QWidget()
        self.participate_vbox = QVBoxLayout(self.participate_widget)
        self.participate_hbox = QHBoxLayout()
        self.participate_addr_label = QLabel("Address")
        self.participate_addr = QLineEdit(self)
        self.participate_amount_label = QLabel("Amount")
        self.participate_amount = QLineEdit(self)
        self.participate_secret_hash_label = QLabel("Secret Hash")
        self.participate_secret_hash = QLineEdit(self)
        self.participate_execute = QPushButton("Execute")
        self.participate_execute.clicked.connect(self.clicked)
        self.participate_publish = QPushButton("Publish Tx")
        self.participate_publish.clicked.connect(self.publish_tx)
        self.participate_publish.setDisabled(True)
        self.participate_hbox.addStretch(1)
        self.participate_hbox.addWidget(self.participate_execute)
        self.participate_hbox.addWidget(self.participate_publish)
        self.participate_vbox.addWidget(self.participate_addr_label)
        self.participate_vbox.addWidget(self.participate_addr)
        self.participate_vbox.addWidget(self.participate_amount_label)
        self.participate_vbox.addWidget(self.participate_amount)
        self.participate_vbox.addWidget(self.participate_secret_hash_label)
        self.participate_vbox.addWidget(self.participate_secret_hash)
        self.participate_vbox.addLayout(self.participate_hbox)
        # redeem
        self.redeem_widget = QWidget()
        self.redeem_vbox = QVBoxLayout(self.redeem_widget)
        self.redeem_hbox = QHBoxLayout()
        self.redeem_contract_label = QLabel("Contract")
        self.redeem_contract = QLineEdit(self)
        self.redeem_contract_tx_label = QLabel("Contract Transaction")
        self.redeem_contract_tx = QLineEdit(self)
        self.redeem_secret_label = QLabel("Secret")
        self.redeem_secret = QLineEdit(self)
        self.redeem_execute = QPushButton("Execute")
        self.redeem_execute.clicked.connect(self.clicked)
        self.redeem_publish = QPushButton("Publish Tx")
        self.redeem_publish.clicked.connect(self.publish_tx)
        self.redeem_publish.setDisabled(True)
        self.redeem_hbox.addStretch(1)
        self.redeem_hbox.addWidget(self.redeem_execute)
        self.redeem_hbox.addWidget(self.redeem_publish)
        self.redeem_vbox.addWidget(self.redeem_contract_label)
        self.redeem_vbox.addWidget(self.redeem_contract)
        self.redeem_vbox.addWidget(self.redeem_contract_tx_label)
        self.redeem_vbox.addWidget(self.redeem_contract_tx)
        self.redeem_vbox.addWidget(self.redeem_secret_label)
        self.redeem_vbox.addWidget(self.redeem_secret)
        self.redeem_vbox.addLayout(self.redeem_hbox)
        # extractsecret
        self.extractsecret_widget = QWidget()
        self.extractsecret_vbox = QVBoxLayout(self.extractsecret_widget)
        self.extractsecret_hbox = QHBoxLayout()
        self.extractsecret_redeem_tx_label = QLabel("Redeem Transaction")
        self.extractsecret_redeem_tx = QLineEdit(self)
        self.extractsecret_secret_hash_label = QLabel("Secret Hash")
        self.extractsecret_secret_hash = QLineEdit(self)
        self.extractsecret_execute = QPushButton("Execute")
        self.extractsecret_execute.clicked.connect(self.clicked)
        self.extractsecret_hbox.addStretch(1)
        self.extractsecret_hbox.addWidget(self.extractsecret_execute)
        self.extractsecret_vbox.addWidget(self.extractsecret_redeem_tx_label)
        self.extractsecret_vbox.addWidget(self.extractsecret_redeem_tx)
        self.extractsecret_vbox.addWidget(self.extractsecret_secret_hash_label)
        self.extractsecret_vbox.addWidget(self.extractsecret_secret_hash)
        self.extractsecret_vbox.addLayout(self.extractsecret_hbox)
        # auditcontract
        self.auditcontract_widget = QWidget()
        self.auditcontract_vbox = QVBoxLayout(self.auditcontract_widget)
        self.auditcontract_hbox = QHBoxLayout()
        self.auditcontract_contract_label = QLabel("Contract")
        self.auditcontract_contract = QLineEdit(self)
        self.auditcontract_contract_tx_label = QLabel("Contract Transaction")
        self.auditcontract_contract_tx = QLineEdit(self)
        self.auditcontract_execute = QPushButton("Execute")
        self.auditcontract_execute.clicked.connect(self.clicked)
        self.auditcontract_hbox.addStretch(1)
        self.auditcontract_hbox.addWidget(self.auditcontract_execute)
        self.auditcontract_vbox.addWidget(self.auditcontract_contract_label)
        self.auditcontract_vbox.addWidget(self.auditcontract_contract)
        self.auditcontract_vbox.addWidget(self.auditcontract_contract_tx_label)
        self.auditcontract_vbox.addWidget(self.auditcontract_contract_tx)
        self.auditcontract_vbox.addLayout(self.auditcontract_hbox)
        # refund
        self.refund_widget = QWidget()
        self.refund_vbox = QVBoxLayout(self.refund_widget)
        self.refund_hbox = QHBoxLayout()
        self.refund_contract_label = QLabel("Contract")
        self.refund_contract = QLineEdit(self)
        self.refund_contract_tx_label = QLabel("Transaction")
        self.refund_contract_tx = QLineEdit(self)
        self.refund_execute = QPushButton("Execute")
        self.refund_execute.clicked.connect(self.clicked)
        self.refund_publish = QPushButton("Publish")
        self.refund_publish.clicked.connect(self.publish_tx)
        self.refund_hbox.addStretch(1)
        self.refund_hbox.addWidget(self.refund_execute)
        self.refund_hbox.addWidget(self.refund_publish)
        self.refund_vbox.addWidget(self.refund_contract_label)
        self.refund_vbox.addWidget(self.refund_contract)
        self.refund_vbox.addWidget(self.refund_contract_tx_label)
        self.refund_vbox.addWidget(self.refund_contract_tx)
        self.refund_vbox.addLayout(self.refund_hbox)
        # add widgets
        self.command_widget.addWidget(self.initiate_widget)
        self.command_widget.addWidget(self.participate_widget)
        self.command_widget.addWidget(self.redeem_widget)
        self.command_widget.addWidget(self.extractsecret_widget)
        self.command_widget.addWidget(self.auditcontract_widget)
        self.command_widget.addWidget(self.refund_widget)

        # result
        self.result_group = QGroupBox("Result")
        self.result_vbox = QVBoxLayout()
        self.result_box = QTextEdit(self)
        self.result_box.setReadOnly(True)
        self.result_vbox.addWidget(self.result_box)
        self.result_group.setLayout(self.result_vbox)

        self.command_vbox.addLayout(self.coin_hbox)
        self.command_vbox.addWidget(self.coin_combo)
        self.command_vbox.addWidget(self.command_label)
        self.command_vbox.addWidget(self.command_combo)
        self.command_vbox.addLayout(self.clear_hbox)
        self.command_vbox.addWidget(self.command_widget)
        self.command_vbox.addWidget(self.result_group)

        # add tabs
        self.tabs = QTabWidget()
        self.tabs.addTab(self.history_tab, "History")
        self.tabs.addTab(self.command_tab, "Commands")

        self.main_vbox.addWidget(self.tabs)
        self.command_widget.setCurrentIndex(0)

        self.setCentralWidget(self.main_window)
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.center()

        self.statusBar()
        self.show()

    def init_menubar(self):
        menubar = QMenuBar()

        # File menu
        file_menu = menubar.addMenu("&File")
        exit_action = QAction("&Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.setStatusTip("Exit application")
        exit_action.triggered.connect(qApp.quit)
        atomicswap_action = QAction("&New AtomicSwap", self)
        atomicswap_action.setShortcut("Ctrl+A")
        atomicswap_action.setStatusTip("Start new atomic swap contract")
        atomicswap_action.triggered.connect(self.atomicswap_window)
        file_menu.addAction(atomicswap_action)
        file_menu.addSeparator()
        file_menu.addAction(exit_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")
        about_atomicswap_qt_action = QAction("About atomicswap-qt", self)
        about_atomicswap_qt_action.setStatusTip("About atomicswap-qt")
        about_atomicswap_qt_action.triggered.connect(self.about_dialog)
        about_qt_action = QAction("About Qt", self)
        about_qt_action.setStatusTip("About Qt")
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
        except Exception:
            error = "Fatal problem has occurred!"
        if error:
            QMessageBox.critical(self, "Error", error, QMessageBox.Ok, QMessageBox.Ok)
            return None
        if refund:
            return asw
        else:
            asw.show()
            return None

    def refund_atomicswap(self, data: dict):
        asw = self.resume_atomicswap(data, True)
        if not asw:
            return
        refund_tx = asw.send_contract_tuple.refund_tx
        if not isinstance(refund_tx, MsgTx):
            return
        send_question = QMessageBox.question(self, "Question",
                                             "Send transaction? ({})".format(refund_tx.get_txid().hex()),
                                             QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if send_question == QMessageBox.No:
            return
        try:
            result = asw.receive_coind.sendrawtransaction(refund_tx.serialize_witness().hex())
            assert result == refund_tx.get_txid().hex()
        except Exception:
            QMessageBox.warning(self, "Failed", "Transaction broadcast was fail.", QMessageBox.Ok, QMessageBox.Ok)
            return
        QMessageBox.information(self, "Succeed", "Transaction was broadcast.", QMessageBox.Ok, QMessageBox.Ok)
        return

    def details_dialog(self, data: dict):
        from .details_dialog import DetailsDialog
        dd = DetailsDialog(self, data)
        dd.exec_()

    def about_dialog(self):
        QMessageBox.about(self,
                          "About atomicswap-qt - atomicswap-qt",
                          "<u><i><h1>atomicswap-qt Version {}</h1></i></u>".format(full_version) + "<br/>" +
                          "Copyright(c) 2011-2020 The Electrum Developers" + "<br/>" +
                          "Copyright(c) 2013-2020 The btcsuite developers" + "<br/>" +
                          "Copyright(c) 2015-2020 The Decred developers" + "<br/>" +
                          "Copyright(c) 2019-2020 The atomicswap-qt developers" + "<br/><br/>" +
                          "This software is rewrite " +
                          "<a href=\"https://github.com/decred/atomicswap\">decred/atomicswap</a> " +
                          "by Python3 and add GUI by PyQt5." + "<br/><br/>" +
                          "<b>This software point</b>" + "<br/>" +
                          "* " + "Full scratch base function" + "<br/>" +
                          "* " + "Only used standard library, pyqt5, requests and pyperclip." + "<br/>" +
                          "* " + "Can use on the gui" + "<br/>" +
                          "* " + "Full compatible with decred/atomicswap" + "<br/><br/>" +
                          "This software is " +
                          "<a href=\"https://github.com/y-chan/atomicswap-qt/blob/master/LICENSE\">" +
                          "MIT License</a>." + " " + "And " +
                          "<a href=\"https://github.com/y-chan/atomicswap-qt\">OSS</a>.")

    def coind_check(self, coin_name: str):
        self.statusBar().showMessage("Make coin data...")
        try:
            req_ver, coind = make_coin_data(coin_name)
        except FileNotFoundError:
            self.statusBar().showMessage("Coin folder not found for your select, "
                                         "please start {} wallet.".format(coin_name))
            return
        except RestartWallet:
            self.statusBar().showMessage("Coin config file not found for your select, "
                                         "so made it by this program. Please restart {} wallet.".format(coin_name))
            return
        except GetConfigError as e:
            self.statusBar().showMessage(str(e))
            return
        self.statusBar().showMessage("Connection check...({})".format(coin_name))
        try:
            version = coind.getnetworkinfo()["version"]
        except InvalidRPCError as e:
            if "backend is down or not responding" in str(e):
                self.statusBar().showMessage("Connection failed.({})".format(coin_name))
                return
            try:
                version = coind.getinfo()["version"]
            except InvalidRPCError:
                self.statusBar().showMessage("Connection failed.({})".format(coin_name))
                return
            except KeyError:
                self.statusBar().showMessage("Can't get version from json.({})".format(coin_name))
                return
        except KeyError:
            self.statusBar().showMessage("Can't get version from json.({})".format(coin_name))
            return
        if req_ver <= version and coind.sign_wallet is False:
            coind.sign_wallet = True
        self.statusBar().showMessage("Connection successful.({})".format(coin_name))
        self.coind = coind
        self.coind_check_label.setText("Coind is OK")
        return

    def command_update(self, cmd_name: str):
        if not (cmd_name in command_list):
            return
        command_index = command_list.index(cmd_name)
        self.command_widget.setCurrentIndex(command_index)

    def clear_box(self):
        index = self.command_combo.currentIndex()
        if index == 0:
            self.initiate_addr.clear()
            self.initiate_amount.clear()
            self.initiate_publish.setDisabled(True)
            self.initiate_result = None
        elif index == 1:
            self.participate_addr.clear()
            self.participate_amount.clear()
            self.participate_secret_hash.clear()
        elif index == 2:
            self.redeem_contract.clear()
            self.redeem_contract_tx.clear()
            self.redeem_secret.clear()
        elif index == 3:
            self.extractsecret_redeem_tx.clear()
            self.extractsecret_secret_hash.clear()
        elif index == 4:
            self.auditcontract_contract.clear()
            self.auditcontract_contract_tx.clear()
        elif index == 5:
            self.refund_contract.clear()
            self.refund_contract_tx.clear()

    def clicked(self):
        if self.coind is None:
            self.result_box.setText("Please reselect coind.")
            return
        index = self.command_combo.currentIndex()
        try:
            if index == 0:
                secret, self.initiate_result = initiate(self.initiate_addr.text(),
                                                        to_satoshis(float(self.initiate_amount.text()),
                                                                    self.coind.decimals),
                                                        self.coind)
                result = initiate_print(secret, self.initiate_result, self.coind)
                self.initiate_publish.setEnabled(True)
            elif index == 1:
                self.participate_result = participate(self.participate_addr.text(),
                                                      to_satoshis(float(self.participate_amount.text()),
                                                                  self.coind.decimals),
                                                      self.participate_secret_hash.text(),
                                                      self.coind)
                result = participate_print(self.participate_result, self.participate_secret_hash.text(), self.coind)
                self.participate_publish.setEnabled(True)
            elif index == 2:
                self.redeem_result, fee = redeem(self.redeem_contract.text(),
                                                 self.redeem_contract_tx.text(),
                                                 self.redeem_secret.text(),
                                                 self.coind)
                result = redeem_print(self.redeem_result,
                                      fee,
                                      self.coind)
                self.redeem_publish.setEnabled(True)
            elif index == 3:
                secret = extractsecret(self.extractsecret_redeem_tx.text(),
                                       self.extractsecret_secret_hash.text(),
                                       self.coind,
                                       False)
                result = extractsecret_print(secret.hex())
            elif index == 4:
                result = auditcontract_print(self.auditcontract_contract.text(),
                                             self.auditcontract_contract_tx.text(),
                                             self.coind)
            elif index == 5:
                self.refund_result, fee = refund(self.refund_contract.text(),
                                                 self.refund_contract_tx.text(),
                                                 self.coind)
                result = refund_print(self.refund_result, fee, self.coind)
                self.refund_publish.setEnabled(True)
            else:
                raise Exception("Missing index.")
            self.result_box.setText(result)
        except Exception as e:
            self.result_box.setText(str(e))
            if index == 0:
                self.initiate_publish.setDisabled(True)
                self.initiate_result = None
            elif index == 1:
                self.participate_publish.setDisabled(True)
                self.participate_result = None
            elif index == 2:
                self.redeem_publish.setDisabled(True)
                self.redeem_result = None
            elif index == 5:
                self.refund_publish.setDisabled(True)
                self.refund_result = None

    def publish_tx(self):
        index = self.command_combo.currentIndex()
        if (not isinstance(self.initiate_result, built_tuple) and index == 0) or \
                (not isinstance(self.participate_result, built_tuple) and index == 1) or \
                (not isinstance(self.redeem_result, MsgTx) and index == 2) or \
                (not isinstance(self.refund_result, MsgTx) and index == 5):
            return

        if index == 0:
            txid = self.initiate_result.contractTxHash.hex()
            tx = self.initiate_result.contractTx.serialize_witness().hex()
        elif index == 1:
            txid = self.participate_result.contractTxHash.hex()
            tx = self.participate_result.contractTx.serialize_witness().hex()
        elif index == 2:
            txid = self.redeem_result.get_txid().hex()
            tx = self.redeem_result.serialize_witness().hex()
        else:
            txid = self.refund_result.get_txid().hex()
            tx = self.refund_result.serialize_witness().hex()
        send_question = QMessageBox.question(self, "Question",
                                             "Send transaction? ({})".format(txid),
                                             QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if send_question == QMessageBox.No:
            return
        try:
            result = self.coind.sendrawtransaction(tx)
        except atomicswap.coind.InvalidRPCError as e:
            QMessageBox.critical(self, "Error", "Fatal problem has occurred!" + "\n" + str(e),
                                 QMessageBox.Ok, QMessageBox.Ok)
            return
        if result != txid:
            QMessageBox.critical(self, "Error", "Fatal problem has occurred!" + "\n" + "Transaction is missing!",
                                 QMessageBox.Ok, QMessageBox.Ok)
            return
        QMessageBox.information(self, "Succeed", "Transaction was broadcast.", QMessageBox.Ok, QMessageBox.Ok)
        return


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
            icon = QPixmap(resource_path("qt", "icons", status_icons[data["Status"]])).scaled(15, 15)
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
        delete_question = QMessageBox.warning(self, "Warning",
                                              "Delete {} to {} atomicswap history?".format(send_coin, receive_coin),
                                              QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if delete_question == QMessageBox.No:
            return
        self.parent.history_db.delete_data(data["SecretHash"])
        self.update()
