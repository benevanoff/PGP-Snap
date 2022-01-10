# PGP-Snap

## What is this?

A desktop application meant to mimick the core functionality of snapchat but with pretty-good-privacy baked in. When a picture is taken the image data in memory is asymmetrically encrypted with the sender and receiver's PGP keys before it is sent to the FTP server on which the encrypted image will be stored until it has been viewed by the reciever at which point it is then deleted from the server. Image data is never written to client storage, encrypted or otherwise.

### Built with
* Python 3
* PyQt5
* OpenCV 2
* PGPy
