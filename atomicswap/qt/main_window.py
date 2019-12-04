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
                             QGridLayout, qApp, QAction, QLineEdit, QComboBox, QLabel,
                             QVBoxLayout, QDialog, QButtonGroup, QRadioButton, QStackedWidget,
                             QMessageBox)
from PyQt5.QtGui import QIcon, QPixmap, QDoubleValidator
from PyQt5.QtCore import pyqtSlot, Qt

from atomicswap.auditcontract import auditcontract
from atomicswap.address import is_p2pkh
from atomicswap.coind import coins, make_coin_data, GetConfigError, RestartWallet, InvalidRPCError
from atomicswap.coin_list import coin_list
from atomicswap.initiate import initiate
from atomicswap.participate import participate

import atomicswap
import requests

icons = "./atomicswap/qt/icons/"

class GUIAtomic(QMainWindow):

    def __init__(self, path: str):
        super().__init__()
        self.title = "atomicswap-qt"
        self.left = 0
        self.top = 0
        self.width = 800
        self.height = 500
        self.page_number = 0
        self.send_coin_name = "bitcoin"
        self.receive_coin_name = "bitcoin"
        self.path = path
        self.send_coind = None
        self.receive_coind = None
        self.initiate_flag = False
        self.secret = ""
        self.send_contract_tuple = None
        self.main_window = QStackedWidget(self)
        # start window
        self.start = QWidget(self)
        self.start_vbox = QVBoxLayout(self.start)
        self.atomic_label = QLabel("<h1>Welcome to Gui-Atomic!</h1>", self)
        self.atomic_label.setAlignment(Qt.AlignCenter)
        self.start_vbox.addWidget(self.atomic_label)
        self.coins_hbox = QHBoxLayout()
        self.send_coin_label = QLabel(self)
        self.send_coin_label.setPixmap(QPixmap(coins + 'bitcoin.png').scaled(128, 128))
        self.send_coin_label.setAlignment(Qt.AlignCenter)
        self.send_label = QLabel("Send currency", self)
        self.send_label.setAlignment(Qt.AlignCenter)
        self.send_coin_combo = QComboBox(self)
        self.send_coin_combo.addItems(coin_list)
        self.send_coin_combo.activated[str].connect(self.on_send_coin)
        self.send_coin_vbox = QVBoxLayout()
        self.send_coin_vbox.addWidget(self.send_coin_label)
        self.send_coin_vbox.addWidget(self.send_label)
        self.send_coin_vbox.addWidget(self.send_coin_combo)
        self.receive_coin_label = QLabel(self)
        self.receive_coin_label.setPixmap(QPixmap(coins + 'bitcoin.png').scaled(128, 128))
        self.receive_coin_label.setAlignment(Qt.AlignCenter)
        self.receive_label = QLabel("Receive currency", self)
        self.receive_label.setAlignment(Qt.AlignCenter)
        self.receive_coin_combo = QComboBox(self)
        self.receive_coin_combo.addItems(coin_list)
        self.receive_coin_combo.activated[str].connect(self.on_receive_coin)
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
        self.quit_button = QPushButton("Quit", self)
        self.start_next_button = QPushButton("Next", self)
        self.start_next_button.setDefault(True)
        self.quit_button.clicked.connect(qApp.quit)
        self.start_next_button.clicked.connect(self.next_page)
        self.start_button_hbox = QHBoxLayout()
        self.start_button_hbox.addStretch(1)
        self.start_button_hbox.addWidget(self.quit_button)
        self.start_button_hbox.addWidget(self.start_next_button)
        self.start_vbox.addLayout(self.coins_hbox)
        self.start_vbox.addLayout(self.start_button_hbox)
        self.main_window.addWidget(self.start)
        # select initiate or participate window
        self.ip = QWidget(self)
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
        self.i_addr_label = QLabel()
        self.i_addr_box = QLineEdit(self)
        self.i_addr_box.textEdited.connect(self.ip_edited)
        self.i_amount_label = QLabel("Amount")
        self.i_amount_box = QLineEdit(self)
        self.i_amount_box.setValidator(QDoubleValidator(0, 999999999999, 8))
        self.i_amount_box.textEdited.connect(self.ip_edited)
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
        self.p_addr_label = QLabel()
        self.p_addr_box = QLineEdit(self)
        self.p_addr_box.textEdited.connect(self.ip_edited)
        self.p_amount_label = QLabel("Amount")
        self.p_amount_box = QLineEdit(self)
        self.p_amount_box.setValidator(QDoubleValidator(0, 999999999999, 8))
        self.p_amount_box.textEdited.connect(self.ip_edited)
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
        self.back_button = QPushButton("Back", self)
        self.next_button_1 = QPushButton("Next", self)
        self.button_hbox = QHBoxLayout()
        self.button_hbox.addStretch(1)
        self.button_hbox.addWidget(self.back_button)
        self.button_hbox.addWidget(self.next_button_1)
        self.next_button_1.setDisabled(True)
        self.back_button.clicked.connect(self.back_page)
        self.next_button_1.clicked.connect(self.next_page)
        self.ip_v_box.addStretch(1)
        self.ip_v_box.addWidget(self.ip_label)
        self.ip_bg.addButton(self.initiate_button, 1)
        self.ip_bg.addButton(self.participate_button, 2)
        self.ip_v_box.addWidget(self.initiate_button)
        self.ip_v_box.addWidget(self.participate_button)
        self.ip_v_box.addWidget(self.ip_widget)
        self.ip_v_box.addLayout(self.button_hbox)
        self.main_window.addWidget(self.ip)
        self.main_window.setCurrentWidget(self.start)
        self.setCentralWidget(self.main_window)
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.center()

        # Create textbox
        # self.textbox = QLineEdit(self)
        # self.textbox.move(20, 20)
        # self.textbox.resize(280, 20)

        self.statusBar().showMessage("Ready")

        # Create a button in the window
        # self.button = QPushButton("Show text", self)
        # self.button.move(20, 60)

        # connect button to function on_click
        # self.button.clicked.connect(self.on_click)
        self.show()

    def initiate(self):
        assert self.main_window.currentIndex() == 1
        self.initiate_flag = True
        self.ip_edited()
        self.ip_widget.setCurrentIndex(1)

    def participate(self):
        assert self.main_window.currentIndex() == 1
        self.initiate_flag = False
        self.ip_edited()
        self.ip_widget.setCurrentIndex(2)

    def ip_edited(self):
        if self.initiate_flag:
            if not self.i_addr_box.text().strip() or not self.i_amount_box.text().strip():
                self.next_button_1.setDisabled(True)
                return
            try:
                p2pkh = is_p2pkh(self.i_addr_box.text().strip(), self.send_coind)
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
                _, _, value = auditcontract(self.contract_box.text().strip(),
                                            self.contract_tx_box.text().strip(),
                                            self.receive_coind)
                label_text = "Contract is Ok, (Your receive amount " + str(value) + " " + self.receive_coind.unit + ")"
                self.contract_status_label.setText(label_text)
            except:
                self.contract_status_label.setText("Contract isn't Ok")
                self.next_button_1.setDisabled(True)
                return
            if not self.p_addr_box.text().strip() or not self.p_amount_box.text().strip():
                self.next_button_1.setDisabled(True)
                return
            try:
                p2pkh = is_p2pkh(self.p_addr_box.text().strip(), self.send_coind)
                amount = float(self.p_amount_box.text().strip())
                if not amount or not p2pkh:
                    raise
            except:
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
        page_number = self.main_window.currentIndex()
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
            self.i_addr_label.setText(f"Send to {self.send_coind.name} address")
            self.p_addr_label.setText(f"Send to {self.send_coind.name} address")
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
                reach_bool, secret_hash, _ = auditcontract(self.contract_box.text().strip(),
                                                           self.contract_tx_box.text().strip(),
                                                           self.receive_coind)
                try:
                    self.send_contract_tuple = participate(self.p_addr_box.text(),
                                                           int(float(self.p_amount_box.text()) * 1e8),
                                                           secret_hash,
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
            return
        self.main_window.setCurrentIndex(page_number + 1)

    def back_page(self):
        page_number = self.main_window.currentIndex()
        self.main_window.setCurrentIndex(page_number - 1)

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
