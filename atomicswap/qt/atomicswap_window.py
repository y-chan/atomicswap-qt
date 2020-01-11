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

from PyQt5.QtWidgets import (QMainWindow, QWidget, QPushButton, QDesktopWidget, QHBoxLayout, QTextEdit, QLineEdit,
                             QComboBox, QLabel, QVBoxLayout, QButtonGroup, QRadioButton, QStackedWidget, QMessageBox)
from PyQt5.QtGui import QPixmap, QDoubleValidator
from PyQt5.QtCore import Qt

from pyperclip import copy
from typing import Tuple

from atomicswap.auditcontract import auditcontract
from atomicswap.address import is_p2pkh, sha256, hash160, hash160_to_b58_address
from atomicswap.coind import make_coin_data, GetConfigError, RestartWallet, InvalidRPCError
from atomicswap.coin_list import coin_list
from atomicswap.initiate import initiate
from atomicswap.participate import participate
from atomicswap.extractsecret import extractsecret
from atomicswap.redeem import redeem
from atomicswap.util import resource_path
from atomicswap.contract import builtTuple, buildRefund
from atomicswap.transaction import deserialize_witness

from .main_window import MainWindow

import atomicswap
import binascii
import requests


class AtomicSwapWindow(QMainWindow):

    def __init__(self, parent: MainWindow):
        super().__init__()
        self.title = "atomicswap - atomicswap-qt"
        self.left = 0
        self.top = 0
        self.width = 600
        self.height = 400
        self.send_coin_name = "Bitcoin"
        self.receive_coin_name = "Litecoin"
        self.parent = parent
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
        self.send_coin_label.setPixmap(QPixmap(
            resource_path('coins', self.send_coin_name.lower() + '.png')).scaled(128, 128))
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
        self.receive_coin_label.setPixmap(QPixmap(
            resource_path('coins', self.receive_coin_name.lower() + '.png')).scaled(128, 128))
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
        self.swap_label.setPixmap(QPixmap(resource_path('qt', 'icons', 'icons8-swap.png')))
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
        self.quit_button.clicked.connect(self.hide)
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
        self.finish_button.clicked.connect(self.hide)
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
                              self.send_coind,
                              False)
                self.redeem_tx_status_label.setText("Transaction is Ok")
            except:
                self.redeem_tx_status_label.setText("Transaction isn't Ok")
                self.next_button_1.setDisabled(True)
                return
        self.next_button_1.setEnabled(True)
        self.next_button_1.setDefault(True)

    def coind_check(self, send: bool, coin_name: str) -> Tuple[bool, str]:
        self.statusBar().showMessage(f"Make {'send' if send else 'receive'} coin data...")
        try:
            req_ver, coind = make_coin_data(coin_name)
        except FileNotFoundError:
            error = f"Coin folder not found for your select, please start {coin_name} wallet."
            self.statusBar().showMessage(error)
            return False, error
        except RestartWallet:
            error = ("Coin config file not found for your select, "
                     f"so made it by this program. Please restart {coin_name} wallet.")
            self.statusBar().showMessage(error)
            return False, error
        except GetConfigError as e:
            self.statusBar().showMessage(str(e))
            return False, str(e)
        self.statusBar().showMessage(f"Connection check...({coin_name})")
        try:
            version = coind.getnetworkinfo()["version"]
        except requests.exceptions.ConnectionError:
            error = f"Connection failed.({coin_name})"
            self.statusBar().showMessage(error)
            return False, error
        except InvalidRPCError:
            try:
                version = coind.getinfo()["version"]
            except InvalidRPCError:
                error = f"Connection failed.{coin_name}"
                self.statusBar().showMessage(error)
                return False, error
            except KeyError:
                error = f"Can't get version from json.{coin_name}"
                self.statusBar().showMessage(error)
                return False, error
        except KeyError:
            error = f"Can't get version from json.{coin_name}"
            self.statusBar().showMessage(error)
            return False, error
        if req_ver <= version:
            coind.sign_wallet = True
        if send:
            self.send_coind = coind
        else:
            self.receive_coind = coind
        self.statusBar().showMessage(f"Connection successful({coin_name})")
        return True, ""

    def on_send_coin(self, text: str):
        split_list = text.split()
        if len(split_list) >= 2:
            split_text = '_'.join(split_list)
        else:
            split_text = text
        self.send_coin_name = text
        self.send_coin_label.setPixmap(QPixmap(
            resource_path('coins', split_text.lower() + '.png')).scaled(128, 128))

    def on_receive_coin(self, text):
        split_list = text.split()
        if len(split_list) >= 2:
            split_text = '_'.join(split_list)
        else:
            split_text = text
        self.receive_coin_name = text
        self.receive_coin_label.setPixmap(QPixmap(
            resource_path('coins', split_text.lower() + '.png')).scaled(128, 128))

    def next_page(self):
        page_number = self.main_widget.currentIndex()
        count = 1
        if page_number == 0:
            if self.send_coin_name == self.receive_coin_name:
                self.statusBar().showMessage("Send coin and receive coin are same. Please reselect coin")
                return
            check, _ = self.coind_check(True, self.send_coin_name)
            if not check:
                return
            check, _ = self.coind_check(False, self.receive_coin_name)
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
                    self.secret_hash = sha256(self.secret)
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
            try:
                result = self.send_coind.sendrawtransaction(self.send_contract_tuple.contractTx.serialize_witness().hex())
            except atomicswap.coind.InvalidRPCError as e:
                QMessageBox.critical(self, 'Error', 'Fatal problem has occurred!' + '\n' + str(e),
                                     QMessageBox.Ok, QMessageBox.Ok)
                self.hide()
                return
            if result != self.send_contract_tuple.contractTxHash.hex():
                QMessageBox.critical(self, 'Error', 'Fatal problem has occurred!' + '\n' + "Transaction is missing!",
                                     QMessageBox.Ok, QMessageBox.Ok)
            self.contract_result.setPlainText("Contract: " + self.send_contract_tuple.contract.hex())
            self.contract_result.append("Contract Transaction: " +
                                        self.send_contract_tuple.contractTx.serialize_witness().hex())
            self.back_button.setDisabled(True)
            self.db_set_data(self.make_db_data(0))
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
                                                self.secret_hash.hex(),
                                                self.send_coind)
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
            try:
                result = self.receive_coind.sendrawtransaction(self.receive_tx.serialize_witness().hex())
            except atomicswap.coind.InvalidRPCError as e:
                QMessageBox.critical(self, 'Error', 'Fatal problem has occurred!' + '\n' + str(e),
                                     QMessageBox.Ok, QMessageBox.Ok)
                self.hide()
                return
            if result != self.receive_tx.get_txid().hex():
                QMessageBox.critical(self, 'Error', 'Fatal problem has occurred!' + '\n' + "Transaction is missing!",
                                     QMessageBox.Ok, QMessageBox.Ok)
            self.redeem_result.setPlainText("Redeem Transaction: " +
                                            self.receive_tx.serialize_witness().hex())
            self.back_button.setDisabled(True)
            self.db_set_data(self.make_db_data(1))
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

    def make_db_data(self, status: int):
        type = "i" if self.initiate_flag else "p"
        try:
            _, _, send_value = auditcontract(self.send_contract_tuple.contract.hex(),
                                             self.send_contract_tuple.contractTx.serialize_witness().hex(),
                                             self.send_coind)
            send_contract = self.send_contract_tuple.contract.hex()
            send_contract_tx = self.send_contract_tuple.contractTx.serialize_witness().hex()
        except:
            send_value = None
            send_contract = ""
            send_contract_tx = ""

        try:
            if self.initiate_flag:
                _, _, receive_value = auditcontract(self.i_p_contract.text().strip(),
                                                    self.i_p_tx.text().strip(),
                                                    self.receive_coind)
                receive_contract = self.i_p_contract.text().strip()
                receive_contract_tx = self.i_p_tx.text().strip()
            else:
                _, _, receive_value = auditcontract(self.contract_box.text().strip(),
                                                    self.contract_tx_box.text().strip(),
                                                    self.receive_coind)
                receive_contract = self.contract_box.text().strip()
                receive_contract_tx = self.contract_tx_box.text().strip()
        except:
            receive_value = None
            receive_contract = ""
            receive_contract_tx = ""

        try:
            send_redeem = self.redeem_tx.text().strip()
        except:
            send_redeem = ""

        try:
            receive_redeem = self.receive_tx.serialize_witness().hex()
        except:
            receive_redeem = ""

        return {
            "Status": status,
            "Type": type,
            "Send": {
                "Coin": self.send_coin_name,
                "Value": send_value,
                "Contract": send_contract,
                "Transaction": send_contract_tx,
                "Redeem": send_redeem  # participator only
            },
            "Receive": {
                "Coin": self.receive_coin_name,
                "Value": receive_value,
                "Contract": receive_contract,
                "Transaction": receive_contract_tx,
                "Redeem": receive_redeem
            },
            "Secret": self.secret.hex(),
            "SecretHash": self.secret_hash.hex()
        }

    def db_set_data(self, data: dict) -> None:
        try:
            self.parent.history_db.delete_data(self.secret_hash.hex())
        except:
            pass
        self.parent.history_db.add_data(data)
        self.parent.history_view.update()

    def resume_atomicswap(self, data: dict) -> str:
        self.button_widget.setCurrentIndex(1)
        status = data["Status"]
        if status == 0 or status == 2:
            if data["Receive"]["Redeem"]:
                return "This contract has been successful."
            self.send_coin_name = data["Send"]["Coin"]
            self.receive_coin_name = data["Receive"]["Coin"]
            check, error = self.coind_check(True, self.send_coin_name)
            if not check:
                return error
            check, error = self.coind_check(False, self.receive_coin_name)
            if not check:
                return error
            self.secret_hash = binascii.a2b_hex(data["SecretHash"])
            if data["Type"] == "i":
                self.initiate_flag = True
                self.secret = binascii.a2b_hex(data["Secret"])
                if sha256(self.secret) != self.secret_hash:
                    return "Secret or SecretHash is missing!"
            else:
                self.contract_box.setText(data["Receive"]["Contract"])
                self.contract_tx_box.setText(data["Receive"]["Transaction"])
            contract = data["Send"]["Contract"]
            contract_bytes = binascii.a2b_hex(contract)
            fee_per_kb, min_fee_per_kb = self.send_coind.get_fee_per_byte()
            contract_tx = deserialize_witness(data["Send"]["Transaction"], self.send_coind)
            refund_tx, refund_fee = buildRefund(contract_bytes, contract_tx,
                                                self.send_coind, fee_per_kb, min_fee_per_kb)
            p2sh_addr_hash = hash160(contract_bytes)
            p2sh_addr = hash160_to_b58_address(p2sh_addr_hash, self.send_coind.p2sh)
            self.send_contract_tuple = builtTuple(contract_bytes, p2sh_addr, contract_tx.get_txid(),
                                                  contract_tx, 0, refund_tx, refund_fee)
            self.contract_result.setPlainText("Contract: " + self.send_contract_tuple.contract.hex())
            self.contract_result.append("Contract Transaction: " +
                                        self.send_contract_tuple.contractTx.serialize_witness().hex())
            self.main_widget.setCurrentIndex(2)
            self.back_button.setDisabled(True)
            self.next_button_1.setEnabled(True)
            return ""
        else:
            return "This contract has been successful!"
