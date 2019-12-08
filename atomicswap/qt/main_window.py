# Copyright (c) 2019 The atomicswap-qt developers
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

from PyQt5.QtWidgets import (QMainWindow, QWidget, QPushButton, QDesktopWidget, QHBoxLayout,
                             QTextEdit, qApp, QAction, QLineEdit, QComboBox, QLabel,
                             QVBoxLayout, QDialog, QButtonGroup, QRadioButton, QStackedWidget,
                             QMessageBox)
from PyQt5.QtGui import QIcon, QPixmap, QDoubleValidator
from PyQt5.QtCore import pyqtSlot, Qt

from pyperclip import copy

from atomicswap.auditcontract import auditcontract
from atomicswap.address import is_p2pkh, sha256
from atomicswap.coind import coins, make_coin_data, GetConfigError, RestartWallet, InvalidRPCError
from atomicswap.coin_list import coin_list
from atomicswap.initiate import initiate
from atomicswap.participate import participate
from atomicswap.extractsecret import extractsecret
from atomicswap.redeem import redeem

import atomicswap
import requests

icons = "./atomicswap/qt/icons/"


class AtomicSwapQt(QMainWindow):

    def __init__(self, path: str):
        super().__init__()
        self.title = "atomicswap-qt"
        self.left = 0
        self.top = 0
        self.width = 800
        self.height = 500
        self.send_coin_name = "Bitcoin"
        self.receive_coin_name = "Litecoin"
        self.path = path
        self.send_coind = None
        self.receive_coind = None
        self.initiate_flag = False
        self.secret = b""
        self.secret_hash = b""
        self.send_contract_tuple = None
        self.receive_tx = None
        self.main_window = QWidget(self)
        self.main_vbox = QVBoxLayout(self.main_window)
        self.main_widget = QStackedWidget()
        self.button_widget = QStackedWidget()

        # start window
        self.start = QWidget(self.main_widget)
        self.start_vbox = QVBoxLayout(self.start)
        self.atomic_label = QLabel("<h1>Welcome to atomicswap-qt!</h1>", self)
        self.atomic_label.setAlignment(Qt.AlignCenter)
        self.start_vbox.addWidget(self.atomic_label)
        self.coins_hbox = QHBoxLayout()
        self.send_coin_label = QLabel(self)
        self.send_coin_label.setPixmap(QPixmap(coins + self.send_coin_name.lower() + '.png').scaled(128, 128))
        self.send_coin_label.setAlignment(Qt.AlignCenter)
        self.send_label = QLabel("Send currency", self)
        self.send_label.setAlignment(Qt.AlignCenter)
        self.send_coin_combo = QComboBox(self)
        self.send_coin_combo.addItems(coin_list)
        self.send_coin_combo.activated[str].connect(self.on_send_coin)
        self.send_coin_index = coin_list.index(self.send_coin_name)
        self.send_coin_combo.setCurrentIndex(self.send_coin_index)
        self.send_coin_vbox = QVBoxLayout()
        self.send_coin_vbox.addWidget(self.send_coin_label)
        self.send_coin_vbox.addWidget(self.send_label)
        self.send_coin_vbox.addWidget(self.send_coin_combo)
        self.receive_coin_label = QLabel(self)
        self.receive_coin_label.setPixmap(QPixmap(coins + self.receive_coin_name.lower() + '.png').scaled(128, 128))
        self.receive_coin_label.setAlignment(Qt.AlignCenter)
        self.receive_label = QLabel("Receive currency", self)
        self.receive_label.setAlignment(Qt.AlignCenter)
        self.receive_coin_combo = QComboBox(self)
        self.receive_coin_combo.addItems(coin_list)
        self.receive_coin_combo.activated[str].connect(self.on_receive_coin)
        self.receive_coin_index = coin_list.index(self.receive_coin_name)
        self.receive_coin_combo.setCurrentIndex(self.receive_coin_index)
        self.receive_coin_vbox = QVBoxLayout()
        self.receive_coin_vbox.addWidget(self.receive_coin_label)
        self.receive_coin_vbox.addWidget(self.receive_label)
        self.receive_coin_vbox.addWidget(self.receive_coin_combo)
        self.swap_label = QLabel(self)
        self.swap_label.setPixmap(QPixmap(icons + 'icons8-swap.png'))
        self.swap_label.setAlignment(Qt.AlignCenter)
        self.swap_vbox = QVBoxLayout()
        self.swap_vbox.addStretch(1)
        self.swap_vbox.addWidget(self.swap_label)
        self.swap_vbox.addStretch(2)
        self.coins_hbox.addLayout(self.send_coin_vbox)
        self.coins_hbox.addLayout(self.swap_vbox)
        self.coins_hbox.addLayout(self.receive_coin_vbox)
        self.start_vbox.addLayout(self.coins_hbox)
        self.main_widget.addWidget(self.start)

        # start buttons
        self.start_button_widget = QWidget()
        self.quit_button = QPushButton("Quit", self)
        self.start_next_button = QPushButton("Next", self)
        self.start_next_button.setDefault(True)
        self.quit_button.clicked.connect(qApp.quit)
        self.start_next_button.clicked.connect(self.next_page)
        self.start_button_hbox = QHBoxLayout(self.start_button_widget)
        self.start_button_hbox.addStretch(1)
        self.start_button_hbox.addWidget(self.quit_button)
        self.start_button_hbox.addWidget(self.start_next_button)
        self.button_widget.addWidget(self.start_button_widget)

        # buttons
        self.normal_button_widget = QWidget()
        self.back_button = QPushButton("Back", self)
        self.next_button_1 = QPushButton("Next", self)
        self.button_hbox = QHBoxLayout(self.normal_button_widget)
        self.button_hbox.addStretch(1)
        self.button_hbox.addWidget(self.back_button)
        self.button_hbox.addWidget(self.next_button_1)
        self.next_button_1.setDisabled(True)
        self.back_button.clicked.connect(self.back_page)
        self.next_button_1.clicked.connect(self.next_page)
        self.button_widget.addWidget(self.normal_button_widget)

        # finish buttons
        self.finish_button_widget = QWidget()
        self.back_button_1 = QPushButton("Back", self)
        self.finish_button = QPushButton("Finish", self)
        self.finish_button_hbox = QHBoxLayout(self.finish_button_widget)
        self.finish_button_hbox.addStretch(1)
        self.finish_button_hbox.addWidget(self.back_button_1)
        self.finish_button_hbox.addWidget(self.finish_button)
        self.back_button_1.hide()
        self.back_button_1.clicked.connect(self.back_page)
        self.finish_button.clicked.connect(qApp.quit)
        self.button_widget.addWidget(self.finish_button_widget)

        # initiate and participate window
        self.ip = QWidget(self.main_widget)
        self.ip_v_box = QVBoxLayout(self.ip)
        self.ip_label = QLabel("Please select initiator or participator.")
        self.ip_bg = QButtonGroup()
        self.initiate_button = QRadioButton("You are initiator. Send coin first.")
        self.participate_button = QRadioButton("You are participator. Receive contract from initiator.")
        self.initiate_button.clicked.connect(self.initiate)
        self.participate_button.clicked.connect(self.participate)
        self.ip_widget = QStackedWidget()
        self.none_widget = QWidget()
        self.none_vbox = QVBoxLayout(self.none_widget)
        self.none_vbox.addStretch(1)
        self.ip_widget.addWidget(self.none_widget)
        self.initiate_widget = QWidget()
        self.initiate_vbox = QVBoxLayout(self.initiate_widget)
        self.i_label = QLabel()
        self.i_addr_label = QLabel()
        self.i_addr_box = QLineEdit(self)
        self.i_addr_box.textEdited.connect(self.ip_edited)
        self.i_amount_label = QLabel("Amount")
        self.i_amount_box = QLineEdit(self)
        self.i_amount_box.setValidator(QDoubleValidator(0, 999999999999, 8))
        self.i_amount_box.textEdited.connect(self.ip_edited)
        self.initiate_vbox.addWidget(self.i_label)
        self.initiate_vbox.addWidget(self.i_addr_label)
        self.initiate_vbox.addWidget(self.i_addr_box)
        self.initiate_vbox.addWidget(self.i_amount_label)
        self.initiate_vbox.addWidget(self.i_amount_box)
        self.initiate_vbox.addStretch(1)
        self.ip_widget.addWidget(self.initiate_widget)
        self.participate_widget = QWidget()
        self.participate_vbox = QVBoxLayout(self.participate_widget)
        self.contract_status_label = QLabel("Contract isn't Ok")
        self.contract_label = QLabel("Contract")
        self.contract_box = QLineEdit(self)
        self.contract_box.textEdited.connect(self.ip_edited)
        self.contract_tx_label = QLabel("Contract Transaction")
        self.contract_tx_box = QLineEdit(self)
        self.contract_tx_box.textEdited.connect(self.ip_edited)
        self.p_label = QLabel()
        self.p_addr_label = QLabel()
        self.p_addr_box = QLineEdit(self)
        self.p_addr_box.textEdited.connect(self.ip_edited)
        self.p_amount_label = QLabel("Amount")
        self.p_amount_box = QLineEdit(self)
        self.p_amount_box.setValidator(QDoubleValidator(0, 999999999999, 8))
        self.p_amount_box.textEdited.connect(self.ip_edited)
        self.participate_vbox.addWidget(self.p_label)
        self.participate_vbox.addWidget(self.contract_status_label)
        self.participate_vbox.addWidget(self.contract_label)
        self.participate_vbox.addWidget(self.contract_box)
        self.participate_vbox.addWidget(self.contract_tx_label)
        self.participate_vbox.addWidget(self.contract_tx_box)
        self.participate_vbox.addWidget(self.p_addr_label)
        self.participate_vbox.addWidget(self.p_addr_box)
        self.participate_vbox.addWidget(self.p_amount_label)
        self.participate_vbox.addWidget(self.p_amount_box)
        self.participate_vbox.addStretch(1)
        self.ip_widget.addWidget(self.participate_widget)
        self.ip_widget.setCurrentIndex(0)
        self.ip_v_box.addStretch(1)
        self.ip_v_box.addWidget(self.ip_label)
        self.ip_bg.addButton(self.initiate_button, 1)
        self.ip_bg.addButton(self.participate_button, 2)
        self.ip_v_box.addWidget(self.initiate_button)
        self.ip_v_box.addWidget(self.participate_button)
        self.ip_v_box.addWidget(self.ip_widget)
        self.main_widget.addWidget(self.ip)

        # confirm window
        self.confirm = QWidget(self.main_widget)
        self.confirm_vbox = QVBoxLayout(self.confirm)
        self.copy_hbox = QHBoxLayout()
        self.copy_label = QLabel("Please copy and send to your trading partner.")
        self.copy_button = QPushButton("Copy")
        self.copy_hbox.addWidget(self.copy_label)
        self.copy_hbox.addStretch(1)
        self.copy_hbox.addWidget(self.copy_button)
        self.contract_result = QTextEdit(self)
        self.contract_result.setReadOnly(True)
        self.copy_button.clicked.connect(lambda: copy(self.contract_result.toPlainText()))
        self.confirm_vbox.addLayout(self.copy_hbox)
        self.confirm_vbox.addWidget(self.contract_result)
        self.main_widget.addWidget(self.confirm)

        # redeem window
        self.redeem = QWidget()
        self.redeem_vbox = QVBoxLayout(self.redeem)
        self.redeem_ip = QStackedWidget()
        self.i_widget = QWidget()
        self.p_widget = QWidget()
        self.i_vbox = QVBoxLayout(self.i_widget)
        self.i_r_label = QLabel("Please input participator's Contract and Contract Transaction.")
        self.i_p_contract_status_label = QLabel("Contract isn't Ok")
        self.i_p_contract_label = QLabel("Contract")
        self.i_p_contract = QLineEdit(self)
        self.i_p_contract.textEdited.connect(self.redeem_edited)
        self.i_p_tx_label = QLabel("Contract Transaction")
        self.i_p_tx = QLineEdit(self)
        self.i_p_tx.textEdited.connect(self.redeem_edited)
        self.i_vbox.addWidget(self.i_r_label)
        self.i_vbox.addWidget(self.i_p_contract_status_label)
        self.i_vbox.addWidget(self.i_p_contract_label)
        self.i_vbox.addWidget(self.i_p_contract)
        self.i_vbox.addWidget(self.i_p_tx_label)
        self.i_vbox.addWidget(self.i_p_tx)
        self.p_vbox = QVBoxLayout(self.p_widget)
        self.redeem_tx_label = QLabel("Please input initiator's redeem transaction.")
        self.redeem_tx_status_label = QLabel("Transaction isn't Ok")
        self.redeem_tx = QLineEdit(self)
        self.redeem_tx.textEdited.connect(self.redeem_edited)
        self.p_vbox.addWidget(self.redeem_tx_label)
        self.p_vbox.addStretch(1)
        self.p_vbox.addWidget(self.redeem_tx_status_label)
        self.p_vbox.addWidget(self.redeem_tx)
        self.redeem_ip.addWidget(self.i_widget)
        self.redeem_ip.addWidget(self.p_widget)
        self.redeem_label = QLabel("Press the Next button to execute redeem.")
        self.redeem_vbox.addWidget(self.redeem_ip)
        self.redeem_vbox.addWidget(self.redeem_label)
        self.redeem_vbox.addStretch(1)
        self.main_widget.addWidget(self.redeem)

        # confirm redeem window (only initiator)
        self.confirm_r = QWidget(self.main_widget)
        self.confirm_r_vbox = QVBoxLayout(self.confirm_r)
        self.copy_r_hbox = QHBoxLayout()
        self.copy_r_label = QLabel("Please copy and send to your trading partner.")
        self.copy_r_button = QPushButton("Copy")
        self.copy_r_hbox.addWidget(self.copy_r_label)
        self.copy_r_hbox.addStretch(1)
        self.copy_r_hbox.addWidget(self.copy_r_button)
        self.redeem_result = QTextEdit(self)
        self.redeem_result.setReadOnly(True)
        self.copy_r_button.clicked.connect(lambda: copy(self.redeem_result.toPlainText()))
        self.confirm_r_vbox.addLayout(self.copy_r_hbox)
        self.confirm_r_vbox.addWidget(self.redeem_result)
        self.main_widget.addWidget(self.confirm_r)

        # success atomicswap window
        self.success = QWidget()
        self.success_vbox = QVBoxLayout(self.success)
        self.success_label = QLabel("<h1>Success Atomic Swap!!!</h1>")
        self.success_vbox.addWidget(self.success_label)
        self.success_vbox.addStretch(1)
        self.main_widget.addWidget(self.success)

        # set start window
        self.main_widget.setCurrentWidget(self.start)
        self.main_vbox.addWidget(self.main_widget)
        self.main_vbox.addWidget(self.button_widget)
        self.setCentralWidget(self.main_window)
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.center()
        self.statusBar().showMessage("Ready")
        self.show()

    def initiate(self):
        assert self.main_widget.currentIndex() == 1
        self.initiate_flag = True
        self.ip_edited()
        self.ip_widget.setCurrentIndex(1)

    def participate(self):
        assert self.main_widget.currentIndex() == 1
        self.initiate_flag = False
        self.ip_edited()
        self.ip_widget.setCurrentIndex(2)

    def ip_edited(self):
        if self.initiate_flag:
            if not self.i_addr_box.text().strip():
                self.next_button_1.setDisabled(True)
                return
            try:
                p2pkh = is_p2pkh(self.i_addr_box.text().strip(), self.send_coind)
                if not p2pkh:
                    self.i_addr_label.setText(f"{self.send_coind.name} address" + " " + "(Address isn't P2PKH)")
                else:
                    self.i_addr_label.setText(f"{self.send_coind.name} address")
                amount = float(self.i_amount_box.text().strip())
                if not amount or not p2pkh:
                    raise
            except:
                self.next_button_1.setDisabled(True)
                return
        else:
            if not self.contract_box.text().strip() or not self.contract_tx_box.text().strip():
                self.next_button_1.setDisabled(True)
                return
            try:
                reach_bool, _, value = auditcontract(self.contract_box.text().strip(),
                                                     self.contract_tx_box.text().strip(),
                                                     self.receive_coind,
                                                     False)
                label_text = "Contract is Ok, (Your receive amount " + str(value) + " " + self.receive_coind.unit + ")"
                self.contract_status_label.setText(label_text)
            except:
                self.contract_status_label.setText("Contract isn't Ok")
                self.next_button_1.setDisabled(True)
                return
            if not reach_bool:
                self.statusBar().showMessage("Your input contract is over 48 hour from contract issue.")
            if not self.p_addr_box.text().strip():
                self.next_button_1.setDisabled(True)
                return
            try:
                p2pkh = is_p2pkh(self.p_addr_box.text().strip(), self.send_coind)
                if not p2pkh:
                    self.p_addr_label.setText(f"{self.send_coind.name} address" + " " + "(Address isn't P2PKH)")
                else:
                    self.p_addr_label.setText(f"{self.send_coind.name} address")
                amount = float(self.p_amount_box.text().strip())
                if not amount or not p2pkh:
                    raise
            except:
                self.next_button_1.setDisabled(True)
                return
        self.next_button_1.setEnabled(True)
        self.next_button_1.setDefault(True)

    def redeem_edited(self):
        if self.initiate_flag:
            try:
                reach_bool, secret_hash, value = auditcontract(self.i_p_contract.text().strip(),
                                                               self.i_p_tx.text().strip(),
                                                               self.receive_coind,
                                                               False)
                if secret_hash != sha256(self.secret):
                    raise
                label_text = "Contract is Ok, (Your receive amount " + str(value) + " " + self.receive_coind.unit + ")"
                self.i_p_contract_status_label.setText(label_text)
            except:
                self.i_p_contract_status_label.setText("Contract isn't Ok")
                self.next_button_1.setDisabled(True)
                return
            if not reach_bool:
                self.statusBar().showMessage("Your input contract is over 24 hour from contract issue.")
        else:
            try:
                extractsecret(self.redeem_tx.text().strip(),
                              self.secret_hash.hex(),
                              False)
                self.redeem_tx_status_label.setText("Transaction is Ok")
            except:
                self.redeem_tx_status_label.setText("Transaction isn't Ok")
                self.next_button_1.setDisabled(True)
                return
        self.next_button_1.setEnabled(True)
        self.next_button_1.setDefault(True)

    def coind_check(self, send: bool, coin_name: str) -> bool:
        self.statusBar().showMessage(f"Make {'send' if send else 'receive'} coin data...")
        try:
            req_ver, coind = make_coin_data(self.path, coin_name)
        except FileNotFoundError:
            self.statusBar().showMessage(f"Coin folder not found for your select, please start {coin_name} wallet.")
            return False
        except RestartWallet:
            self.statusBar().showMessage("Coin config file not found for your select, "
                                         f"so made it by this program. Please restart {coin_name} wallet.")
            return False
        except GetConfigError as e:
            self.statusBar().showMessage(str(e))
            return False
        self.statusBar().showMessage(f"Connection check...({coin_name})")
        try:
            version = coind.getnetworkinfo()["version"]
        except requests.exceptions.ConnectionError:
            self.statusBar().showMessage(f"Connection failed.({coin_name})")
            return False
        except InvalidRPCError:
            try:
                version = coind.getinfo()["version"]
            except InvalidRPCError:
                self.statusBar().showMessage(f"Connection failed.{coin_name}")
                return False
            except KeyError:
                self.statusBar().showMessage(f"Can't get version from json.{coin_name}")
                return False
        except KeyError:
            self.statusBar().showMessage(f"Can't get version from json.{coin_name}")
            return False
        if req_ver <= version:
            coind.sign_wallet = True
        if send:
            self.send_coind = coind
        else:
            self.receive_coind = coind
        self.statusBar().showMessage(f"Connection successful({coin_name})")
        return True

    def on_send_coin(self, text: str):
        split_list = text.split()
        if len(split_list) >= 2:
            split_text = '_'.join(split_list)
        else:
            split_text = text
        self.send_coin_name = text
        self.send_coin_label.setPixmap(QPixmap(coins + split_text.lower() + '.png').scaled(128, 128))

    def on_receive_coin(self, text):
        split_list = text.split()
        if len(split_list) >= 2:
            split_text = '_'.join(split_list)
        else:
            split_text = text
        self.receive_coin_name = text
        self.receive_coin_label.setPixmap(QPixmap(coins + split_text.lower() + '.png').scaled(128, 128))

    def next_page(self):
        page_number = self.main_widget.currentIndex()
        count = 1
        if page_number == 0:
            if self.send_coin_name == self.receive_coin_name:
                self.statusBar().showMessage("Send coin and receive coin are same. Please reselect coin")
                return
            check = self.coind_check(True, self.send_coin_name)
            if not check:
                return
            check = self.coind_check(False, self.receive_coin_name)
            if not check:
                return
            self.i_label.setText(f"Please input participator's {self.send_coind.name} address and send amount.")
            self.p_label.setText("Please input initiator's Contract, Contract Transaction and " +
                                 f"{self.send_coind.name} address and send amount.")
            self.i_addr_label.setText(f"{self.send_coind.name} address")
            self.p_addr_label.setText(f"{self.send_coind.name} address")
            self.button_widget.setCurrentIndex(1)
        elif page_number == 1:
            if self.initiate_flag:
                try:
                    self.secret, self.send_contract_tuple = initiate(self.i_addr_box.text(),
                                                                     int(float(self.i_amount_box.text()) * 1e8),
                                                                     self.send_coind)
                except atomicswap.coind.InvalidRPCError as e:
                    self.statusBar().showMessage(str(e))
                    return
            else:
                _, self.secret_hash, _ = auditcontract(self.contract_box.text().strip(),
                                                       self.contract_tx_box.text().strip(),
                                                       self.receive_coind)
                try:
                    self.send_contract_tuple = participate(self.p_addr_box.text(),
                                                           int(float(self.p_amount_box.text()) * 1e8),
                                                           self.secret_hash.hex(),
                                                           self.send_coind)
                except atomicswap.coind.InvalidRPCError as e:
                    self.statusBar().showMessage(str(e))
                    return
            send_question = QMessageBox.question(self, 'Question',
                                                 f"Send transaction? ({self.send_contract_tuple.contractTxHash.hex()})",
                                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if send_question == QMessageBox.No:
                return
            result = self.send_coind.sendrawtransaction(self.send_contract_tuple.contractTx.serialize_witness().hex())
            assert result == self.send_contract_tuple.contractTxHash.hex()
            self.contract_result.setPlainText("Contract: " + self.send_contract_tuple.contract.hex())
            self.contract_result.append("Contract Transaction: " +
                                        self.send_contract_tuple.contractTx.serialize_witness().hex())
            self.back_button.setDisabled(True)
        elif page_number == 2:
            if not self.initiate_flag:
                self.redeem_ip.setCurrentIndex(1)
            else:
                self.redeem_ip.setCurrentIndex(0)
            self.back_button.setEnabled(True)
            self.next_button_1.setDisabled(True)
        elif page_number == 3:
            if not self.initiate_flag:
                try:
                    self.secret = extractsecret(self.redeem_tx.text().strip(),
                                                self.secret_hash.hex())
                    self.receive_tx = redeem(self.contract_box.text().strip(),
                                             self.contract_tx_box.text().strip(),
                                             self.secret.hex(),
                                             self.receive_coind)
                except atomicswap.coind.InvalidRPCError as e:
                    self.statusBar().showMessage(str(e))
                    return
                count += 1
            else:
                try:
                    self.receive_tx = redeem(self.i_p_contract.text().strip(),
                                             self.i_p_tx.text().strip(),
                                             self.secret.hex(),
                                             self.receive_coind)
                except atomicswap.coind.InvalidRPCError as e:
                    self.statusBar().showMessage(str(e))
                    return
            send_question = QMessageBox.question(self, 'Question',
                                                 f"Send transaction? ({self.receive_tx.get_txid().hex()})",
                                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if send_question == QMessageBox.No:
                return
            result = self.receive_coind.sendrawtransaction(self.receive_tx.serialize_witness().hex())
            assert result == self.receive_tx.get_txid().hex()
            self.redeem_result.setPlainText("Redeem Transaction: " +
                                            self.recive_tx.serialize_witness().hex())
            self.back_button.setDisabled(True)
            if not self.initiate_flag:
                self.button_widget.setCurrentIndex(2)
        elif page_number == 4:
            self.button_widget.setCurrentIndex(2)
            self.back_button_1.show()
        self.main_widget.setCurrentIndex(page_number + count)
        self.statusBar().showMessage("")

    def back_page(self):
        page_number = self.main_widget.currentIndex()
        count = 1
        self.main_widget.setCurrentIndex(page_number - count)
        if page_number == 1:
            self.button_widget.setCurrentIndex(0)
        elif page_number == 3:
            self.back_button.setDisabled(True)
            self.next_button_1.setEnabled(True)
        elif page_number == 5:
            self.button_widget.setCurrentIndex(1)
            self.back_button.setDisabled(True)

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
