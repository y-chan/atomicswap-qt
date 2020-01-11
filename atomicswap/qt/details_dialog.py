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

from PyQt5.QtWidgets import (QDialog, QDesktopWidget, QWidget, QGroupBox,
                             QVBoxLayout, QLabel, QLineEdit, QTextEdit)

from .main_window import MainWindow

class DetailsDialog(QDialog):
    def __init__(self, parent: MainWindow, data: dict):
        super().__init__()
        self.title = "details - atomicswap-qt"
        self.left = 0
        self.top = 0
        self.width = 600
        self.height = 600
        self.parent = parent
        self.data = data
        self.main_vbox = QVBoxLayout(self)

        # details
        self.i_label = QGroupBox("Initiator")
        self.i_vbox = QVBoxLayout()
        self.p_label = QGroupBox("Participator")
        self.p_vbox = QVBoxLayout()
        self.secret_label = QLabel("Secret")
        self.secret_hash_label = QLabel("Secret Hash")
        self.s_contract_label = QLabel("Contract")
        self.r_contract_label = QLabel("Contract")
        self.s_contract_tx_label = QLabel("Transaction")
        self.r_contract_tx_label = QLabel("Transaction")
        self.secret_text = QLineEdit(self)
        self.secret_text.setReadOnly(True)
        self.secret_text.setText(self.data["Secret"])
        self.secret_hash_text = QLineEdit(self)
        self.secret_hash_text.setReadOnly(True)
        self.secret_hash_text.setText(self.data["SecretHash"])
        self.s_contract_text = QTextEdit(self)
        self.s_contract_text.setReadOnly(True)
        self.s_contract_text.setText(self.data["Send"]["Contract"])
        self.r_contract_text = QTextEdit(self)
        self.r_contract_text.setReadOnly(True)
        self.r_contract_text.setText(self.data["Receive"]["Contract"])
        self.s_contract_tx_text = QTextEdit(self)
        self.s_contract_tx_text.setReadOnly(True)
        self.s_contract_tx_text.setText(self.data["Send"]["Transaction"])
        self.r_contract_tx_text = QTextEdit(self)
        self.r_contract_tx_text.setReadOnly(True)
        self.r_contract_tx_text.setText(self.data["Receive"]["Transaction"])
        if self.data["Type"] == "i":
            self.i_vbox.addWidget(self.s_contract_label)
            self.i_vbox.addWidget(self.s_contract_text)
            self.i_vbox.addWidget(self.s_contract_tx_label)
            self.i_vbox.addWidget(self.s_contract_tx_text)
            self.i_vbox.addStretch(1)
        else:
            self.i_vbox.addWidget(self.r_contract_label)
            self.i_vbox.addWidget(self.r_contract_text)
            self.i_vbox.addWidget(self.r_contract_tx_label)
            self.i_vbox.addWidget(self.r_contract_tx_text)
        self.i_label.setLayout(self.i_vbox)
        self.main_vbox.addWidget(self.i_label)
        if self.data["Type"] == "i":
            self.p_vbox.addWidget(self.r_contract_label)
            self.p_vbox.addWidget(self.r_contract_text)
            self.p_vbox.addWidget(self.r_contract_tx_label)
            self.p_vbox.addWidget(self.r_contract_tx_text)
        else:
            self.p_vbox.addWidget(self.s_contract_label)
            self.p_vbox.addWidget(self.s_contract_text)
            self.p_vbox.addWidget(self.s_contract_tx_label)
            self.p_vbox.addWidget(self.s_contract_tx_text)
        self.p_label.setLayout(self.p_vbox)
        self.main_vbox.addWidget(self.p_label)
        self.main_vbox.addWidget(self.secret_label)
        self.main_vbox.addWidget(self.secret_text)
        self.main_vbox.addWidget(self.secret_hash_label)
        self.main_vbox.addWidget(self.secret_hash_text)
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.center()

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
