from PyQt5 import QtGui
from PyQt5.QtWidgets import QMainWindow, QWidget, QApplication, QAction, QLabel, QVBoxLayout, QPushButton, QFileDialog
from PyQt5.QtGui import QPixmap
import sys
import cv2
from PyQt5.QtCore import pyqtSignal, pyqtSlot, Qt, QThread
import numpy as np
from ftplib import FTP
import io
import pgpy
import base64

disply_width = 640
display_height = 480

ftp_host = '127.0.0.1' #change ftp host and username/password as necessary
username = ''
password = ''

def convert_cv_qt(cv_img): # this helper taken from https://gist.github.com/docPhil99/ca4da12c9d6f29b9cea137b617c7b8b1
    """Convert from an opencv image to QPixmap"""
    rgb_image = cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB)
    h, w, ch = rgb_image.shape
    bytes_per_line = ch * w
    convert_to_Qt_format = QtGui.QImage(rgb_image.data, w, h, bytes_per_line, QtGui.QImage.Format_RGB888)
    p = convert_to_Qt_format.scaled(disply_width, display_height, Qt.KeepAspectRatio)
    return QPixmap.fromImage(p)

class VideoThread(QThread):
    change_pixmap_signal = pyqtSignal(np.ndarray)

    def __init__(self):
        super().__init__()
        self._run_flag = True

    def run(self):
        # capture from web cam
        cap = cv2.VideoCapture(0) # todo add input toggling
        while self._run_flag:
            ret, cv_img = cap.read()
            retTwo, buf = cv2.imencode('.jpg', cv_img)
            self.img = base64.b64encode(buf)
            if ret:
                self.change_pixmap_signal.emit(cv_img)
        cap.release()

    def stop(self):
        """Sets run flag to False and waits for thread to finish"""
        self._run_flag = False
        self.wait()

    def encrypt(self, img, pubkey):
        message = pgpy.PGPMessage.new(img)
        encrypted_message = pubkey.encrypt(message)
        return str(encrypted_message)

    def snap(self):
        img = self.img # save image before selecting recipient
        keyfile, r = QFileDialog.getOpenFileName(None, "Recipient public key","", "Asc Files (*.asc)")
        # todo check result
        pubkey, _ = pgpy.PGPKey.from_file(keyfile)
        encrypted_msg = self.encrypt(img, pubkey)
        del img
        
        ftp = FTP(ftp_host)
        ftp.login(user=username, passwd=password)

        desired_exists = False
        desired_dir = pubkey.fingerprint.keyid # easy identifier
        for name, info in ftp.mlsd():
            if name == desired_dir:
                desired_exists = True
                break
        if not desired_exists:
            ftp.mkd(desired_dir)
            
        ftp.cwd(desired_dir)
        filename = desired_dir # todo make this unique by sender maybe diffie helman w sender-recipient idk
        
        stream = io.BytesIO()
        stream.write(encrypted_msg.encode())
        stream.seek(0)
        
        ftp.storbinary('STOR '+filename, stream)
        print("snapped")
        ftp.quit()

class CameraFeed(QWidget):
    def __init__(self):
        super().__init__()
        # create the label that holds the image
        self.image_label = QLabel(self)
        self.image_label.resize(disply_width, display_height)

        self.snap_button = QPushButton("Snap photo")
        self.inbox_button = QPushButton("Inbox")
        vbox = QVBoxLayout()
        vbox.addWidget(self.image_label)
        vbox.addWidget(self.snap_button)
        vbox.addWidget(self.inbox_button)
        self.setLayout(vbox)

        self.thread = VideoThread()
        self.thread.change_pixmap_signal.connect(self.update_image) # connect its signal to the update_image slot
        self.snap_button.clicked.connect(self.thread.snap)    
        self.thread.start()

    def closeEvent(self, event):
        self.thread.stop()
        event.accept()

    @pyqtSlot(np.ndarray)
    def update_image(self, cv_img):
        """Updates the image_label with a new opencv image"""
        qt_img = convert_cv_qt(cv_img)
        self.image_label.setPixmap(qt_img)

class Preview(QWidget):
    
    def __init__(self, keypath):
        super().__init__()
        self.seckey, _ = pgpy.PGPKey.from_file(keypath)
        self.img_label = QLabel(self)
        self.img_label.setText("Empty")
        self.img_label.resize(disply_width, display_height)
        self.back_button = QPushButton("Back");

        vbox = QVBoxLayout()
        vbox.addWidget(self.img_label)
        vbox.addWidget(self.back_button)
        self.setLayout(vbox)
        
        self.fetch_img()

    def decrypt(self, data):
        msg = pgpy.PGPMessage.from_blob(data)
        plaintext = self.seckey.decrypt(msg)
        return plaintext.message

    def fetch_callback(self, data):
        self.remote_img.write(data)

    def fetch_img(self):
        ftp = FTP(ftp_host)
        ftp.login(user=username, passwd=password)
        
        desired_dir = self.seckey.pubkey.fingerprint.keyid
        desired_exists = False
        for name, info in ftp.mlsd():
            if name == desired_dir:
                desired_exists = True
                break
        if not desired_exists:
            print("nothing to fetch")
            ftp.quit()
            return
        ftp.cwd(desired_dir)
        self.remote_img = io.BytesIO()
        ftp.retrbinary('RETR '+desired_dir, self.fetch_callback)
        ftp.delete(desired_dir)
        ftp.quit()
        self.remote_img.seek(0)
        decrypted_img = self.decrypt(self.remote_img.read().decode())
        decoded_img = base64.b64decode(decrypted_img)
        img_as_np = np.frombuffer(decoded_img, dtype=np.uint8)
        cv_img = cv2.imdecode(img_as_np, flags=1)
        qt_img = convert_cv_qt(cv_img)
        self.img_label.setPixmap(qt_img)

class Login(QWidget):

    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        label = QLabel("Login with your PGP secret key")
        button = QPushButton("Select key file")
        vbox = QVBoxLayout()
        vbox.addWidget(label)
        vbox.addWidget(button)
        self.setLayout(vbox)
        button.clicked.connect(self.loginClicked)

    def loginClicked(self):
        path, r = QFileDialog.getOpenFileName(None, "Select PGP private key","", "Asc Files (*.asc)")
        # todo validation
        self.callback(path)

class App(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PGP-Snap")
        loginWidget = Login(self.loginCallback)
        self.setCentralWidget(loginWidget) # begin with camera view

        menuBar = self.menuBar()
        settings_bar = menuBar.addMenu("Settings")
        login_action = QAction("Choose encryption key", self)
        settings_bar.addAction(login_action)
        login_action.triggered.connect(self.chooseSecretKey)
        
        self.show()

    def loginCallback(self, filepath):
        self.keyfile = filepath
        self.loadCameraFeed()

    def chooseSecretKey(self):
        self.keyfile, r = QFileDialog.getOpenFileName(None, "Select PGP private key","", "Asc Files (*.asc)")
        # todo check result

    def loadPreview(self):
        # todo handle no key selected exception
        self.centralWidget().close() # clear slate
        preview = Preview(self.keyfile)
        self.setCentralWidget(preview)
        preview.back_button.clicked.connect(self.loadCameraFeed)

    def loadCameraFeed(self):
        self.centralWidget().close()
        feed = CameraFeed()
        self.setCentralWidget(feed)
        feed.inbox_button.clicked.connect(self.loadPreview)  

    def closeEvent(self, event):
        self.centralWidget().close()

if __name__=="__main__":

    app = QApplication(sys.argv)
    a = App()
    sys.exit(app.exec_())
