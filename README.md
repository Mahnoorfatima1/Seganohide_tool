# Steganography Tool

This Python application uses Tkinter to create a graphical user interface (GUI) for steganography.  It allows users to hide data within image, audio (WAV), and video (MP4) files, and to extract that hidden data. The application uses a password-based encryption method to protect the hidden data.

## Features

* **Data Hiding:** Embeds text messages within:
    * Image files (.png, .jpg, .jpeg)
    * Audio files (.wav)
    * Video files (.mp4)
* **Data Extraction:** Retrieves hidden messages from the supported file types.
* **Password Protection:** Encrypts the hidden data using a password for secure steganography.
* **User-Friendly Interface:**  Provides a simple and intuitive GUI using Tkinter.
* **File Selection:** Uses `filedialog` for easy file browsing and selection.
* **Cross-Platform Compatibility:** As a Python application using Tkinter, it has potential for cross-platform compatibility (Windows, macOS, Linux).

## How to Run

1. **Prerequisites:** Make sure you have Python 3 installed. You'll also need the following libraries, which you can install using pip:
   ```bash
   pip install tkinter pillow wave opencv-python
tkinter: Included with most Python installations.
pillow: For image processing (PIL Fork).
wave: For handling WAV audio files.
opencv-python: For video processing.
Clone or Download: Clone the repository (if available) or download the Python script (e.g., steganography_app.py).

Run the Script: Open a terminal or command prompt, navigate to the directory where you saved the script, and run it:

Bash

python steganography_app.py
Usage
Welcome Page: The application starts with a welcome page that provides a brief overview of steganography and the tool's capabilities. Click "Let's Start" to proceed to the main interface.

Main Interface: The main interface has two tabs: "Encode" and "Decode."

Encode Tab:

Select the file type (Image, Audio, or Video).
Click "Select File" to choose the file you want to use for hiding data.
A password prompt will appear. Enter a password to encrypt the data.
Enter the message you want to hide in the dialog box.
The encoded file will be saved.
Decode Tab:

Click "Select File to Decode" to choose the file containing the hidden data.
A password prompt will appear. Enter the same password used for encoding.
The decoded message will be displayed.
Code Overview
The code is structured into a SteganographyApp class, which handles the GUI and the steganography logic.  Key functions include:

encode_file(): Handles encoding data into the selected file.
decode_file(): Handles decoding data from the selected file.
encrypt_message(): Encrypts the message using a password.
decrypt_message(): Decrypts the message.
encode_image(), decode_image(): Functions for image steganography.
encode_audio(), decode_audio(): Functions for audio steganography.
encode_video(), decode_video(): Functions for video steganography.
