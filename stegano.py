import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk

import wave
import os
import hashlib
import cv2
import numpy as np
from typing import Optional

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Tool")
        self.root.geometry("1000x700")

        # Load and set the background image (adjust path if needed)
        try:
            self.bg_image = Image.open(r"C:\\Users\\user\\Downloads\\picbg.jpg")

            # Get screen width and height after making fullscreen
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()

            self.bg_image = self.bg_image.resize((screen_width, screen_height), Image.LANCZOS) # Resize to screen dimensions
            self.bg_photo = ImageTk.PhotoImage(self.bg_image) # Keep a reference!
            bg_label = tk.Label(self.root, image=self.bg_photo)
            bg_label.place(x=0, y=0, width=screen_width, height=screen_height) # Cover the whole screen

        except FileNotFoundError:
            print("Background image not found.")
            # Handle the error, perhaps use a default color or image.
            self.root.configure(bg="gray") # Example: set background to gray

        
        self.canvas = tk.Canvas(root, width=1000, height=700)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.create_image(0, 0, image=self.bg_photo, anchor="nw")
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Custom styles
        self.style.configure('TButton', padding=10, font=('Helvetica', 12, 'bold'), background="#D2B48C", foreground="black", borderwidth=0)
        self.style.map('TButton', background=[('active', 'white')])  # Hover effect
        self.style.configure('TLabel', font=('Helvetica', 14), background="#806349", foreground="black")
        self.style.configure('TFrame', background="#806349")
        self.style.configure('TNotebook', background="#C4A484", borderwidth=0)
        self.style.configure('TNotebook.Tab', font=('Helvetica', 12, 'bold'), padding=[10, 5], background="#463425", foreground="white", borderwidth=0)
        self.style.map('TNotebook.Tab', background=[('selected', '#806349')], foreground=[('selected', 'white')])

        self.current_frame = None
        self.show_welcome_page()

    def show_welcome_page(self):
        if self.current_frame:
            self.current_frame.destroy()
        
        self.current_frame = ttk.Frame(self.root, padding="20", style='TFrame')
        self.current_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Welcome message
        ttk.Label(
            self.current_frame,
            text="Welcome to Steganography Tool",
            font=('Helvetica', 28, 'bold'),
            style='TLabel'
        ).grid(row=0, column=0, pady=20)
        
        # Project information
        info_text = """
        Steganography is the practice of concealing messages within other non-secret data.
        This tool allows you to:
        • Hide data in images, audio, and video files
        • Protect your hidden data with passwords
        • Extract hidden data from files
        """
        ttk.Label(
            self.current_frame,
            text=info_text,
            font=('Helvetica', 14),
            justify=tk.LEFT,
            style='TLabel'
        ).grid(row=1, column=0, pady=20)
        
        # Start button
        ttk.Button(
            self.current_frame,
            text="Let's Start",
            command=self.show_main_page,
            style='TButton'
        ).grid(row=2, column=0, pady=20)
    
    def show_main_page(self):
        if self.current_frame:
            self.current_frame.destroy()
        
        self.current_frame = ttk.Frame(self.root, padding="20", style='TFrame')
        self.current_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Create notebook for tabs
        notebook = ttk.Notebook(self.current_frame, style='TNotebook')
        notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Encode tab
        encode_frame = ttk.Frame(notebook, padding="20", style='TFrame')
        notebook.add(encode_frame, text='Encode')
        
        ttk.Label(encode_frame, text="Select file type:", style='TLabel').grid(row=0, column=0, pady=10, sticky=tk.W)
        file_types = ['Image', 'Audio', 'Video']
        self.encode_file_type = tk.StringVar(value=file_types[0])
        
        for i, ft in enumerate(file_types):
            ttk.Radiobutton(
                encode_frame,
                text=ft,
                variable=self.encode_file_type,
                value=ft,
                style='TLabel'
            ).grid(row=0, column=i+1, padx=10, pady=10, sticky=tk.W)
        
        ttk.Button(
            encode_frame,
            text="Select File",
            command=self.select_file_encode,
            style='TButton'
        ).grid(row=3, column=0, columnspan=4, pady=20)
        
        # Decode tab
        decode_frame = ttk.Frame(notebook, padding="20", style='TFrame')
        notebook.add(decode_frame, text='Decode')
        
        ttk.Button(
            decode_frame,
            text="Select File to Decode",
            command=self.select_file_decode,
            style='TButton'
        ).grid(row=0, column=0, pady=20)
        
        # Back button
        ttk.Button(
            self.current_frame,
            text="Back to Welcome",
            command=self.show_welcome_page,
            style='TButton'
        ).grid(row=1, column=0, pady=20)
    
    def select_file_encode(self):
        file_type = self.encode_file_type.get().lower()
        filetypes = {
            'image': [('Image files', '*.png *.jpg *.jpeg')],
            'audio': [('Audio files', '*.wav')],
            'video': [('Video files', '*.mp4')]
        }
        
        filename = filedialog.askopenfilename(
            title=f"Select {file_type} file",
            filetypes=filetypes[file_type]
        )
        
        if filename:  # Check if a file was selected
            self.prompt_password(filename, mode='encode')
        else:
            messagebox.showerror("Error", "No file selected for encoding. Please select a valid file.")

    
    def select_file_decode(self):
        filename = filedialog.askopenfilename(
            title="Select file to decode",
            filetypes=[
                ('All supported files', '*.png *.jpg *.jpeg *.wav *.mp4'),
                ('Image files', '*.png *.jpg *.jpeg'),
                ('Audio files', '*.wav'),
                ('Video files', '*.mp4')
            ]
        )
        
        if filename:  # Check if a file was selected
            self.prompt_password(filename, mode='decode')
        else:
            messagebox.showerror("Error", "No file selected for decoding. Please select a valid file.")

    
    def prompt_password(self, filename: str, mode: str):
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter Password")
        dialog.geometry("400x200")
        dialog.configure(bg="#806349")
        
        ttk.Label(
            dialog,
            text="Enter password:",
            style='TLabel'
        ).grid(row=0, column=0, pady=20, padx=20)
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(
            dialog,
            show="*",
            textvariable=password_var,
            font=('Helvetica', 12)
        )
        password_entry.grid(row=0, column=1, pady=20, padx=20)
        
        def process():
            password = password_var.get()
            if not password:  # Check for empty password
                messagebox.showerror("Error", "Password cannot be empty! Please enter a password.")
                return  # Exit the function if password is empty

            dialog.destroy()
            if mode == 'encode':
                self.encode_file(filename, password)
            else:
                self.decode_file(filename, password)
        
        ttk.Button(
            dialog,
            text="OK",
            command=process,
            style='TButton'
        ).grid(row=1, column=0, columnspan=2, pady=20)
    
    def encode_file(self, filename: str, password: str):
        try:
            file_ext = os.path.splitext(filename)[1].lower()
            
            # Get message to hide
            message = tk.simpledialog.askstring(
                "Input",
                "Enter the message to hide:",
                parent=self.root
            )
            
            if not message:
                messagebox.showerror("Error", "Message cannot be empty! Please enter a message to hide.")
                return
            
            # Encrypt message with password
            encrypted = self.encrypt_message(message, password)
            
            # Prefix the encrypted data with its length
            data_length = len(encrypted).to_bytes(4, 'big')
            data_to_hide = data_length + encrypted
            
            if file_ext in ['.png', '.jpg', '.jpeg']:
                self.encode_image(filename, data_to_hide)
            elif file_ext == '.wav':
                self.encode_audio(filename, data_to_hide)
            elif file_ext == '.mp4':
                self.encode_video(filename, data_to_hide)
            
            messagebox.showinfo("Success", "Data encoded successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {str(e)}. Please check the file and try again.")

    
    def decode_file(self, filename: str, password: str):
        try:
            file_ext = os.path.splitext(filename)[1].lower()
            
            if file_ext in ['.png', '.jpg', '.jpeg']:
                encrypted = self.decode_image(filename)
            elif file_ext == '.wav':
                encrypted = self.decode_audio(filename)
            elif file_ext == '.mp4':
                encrypted = self.decode_video(filename)
            
            # Extract the length of the encrypted data
            data_length = int.from_bytes(encrypted[:4], 'big')
            encrypted_data = encrypted[4:4+data_length]
            
            # Decrypt message with password
            message = self.decrypt_message(encrypted_data, password)
            
            if message:
                messagebox.showinfo("Success", f"Decoded message: {message}")
            else:
                messagebox.showerror("Error", "Invalid password or no hidden message found!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {str(e)}. Please check the file and try again.")

    
    def encrypt_message(self, message: str, password: str) -> bytes:
        key = hashlib.sha256(password.encode()).digest()
        encrypted = bytearray()
        for i, c in enumerate(message.encode()):
            encrypted.append(c ^ key[i % len(key)])
        return bytes(encrypted)
    
    def decrypt_message(self, encrypted: bytes, password: str) -> Optional[str]:
        try:
            key = hashlib.sha256(password.encode()).digest()
            decrypted = bytearray()
            for i, c in enumerate(encrypted):
                decrypted.append(c ^ key[i % len(key)])
            return decrypted.decode()
        except:
            return None
    
    def encode_image(self, filename: str, data: bytes):
        img = Image.open(filename)
        width, height = img.size
        pixels = list(img.getdata())
        
        if len(pixels[0]) == 3:  # RGB
            channels = 3
        else:  # RGBA
            channels = 4
        
        # Convert data to bits
        bits = ''.join([format(b, '08b') for b in data])
        
        if len(bits) > len(pixels) * channels:
            raise ValueError("Data too large for this image")
        
        # Modify least significant bits
        new_pixels = []
        bit_idx = 0
        
        for pixel in pixels:
            new_pixel = list(pixel)
            for i in range(channels):
                if bit_idx < len(bits):
                    new_pixel[i] = (new_pixel[i] & ~1) | int(bits[bit_idx])
                    bit_idx += 1
            new_pixels.append(tuple(new_pixel))
        
        # Save modified image
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_pixels)
        
        save_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if save_path:
            new_img.save(save_path)
    
    def decode_image(self, filename: str) -> bytes:
        img = Image.open(filename)
        pixels = list(img.getdata())
        
        if len(pixels[0]) == 3:  # RGB
            channels = 3
        else:  # RGBA
            channels = 4
        
        # Extract bits from least significant bits
        bits = ''
        for pixel in pixels:
            for i in range(channels):
                bits += str(pixel[i] & 1)
        
        # Convert bits to bytes
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) == 8:
                bytes_data.append(int(byte, 2))
        
        return bytes(bytes_data)
    
    def encode_audio(self, filename: str, data: bytes):
        with wave.open(filename, 'rb') as wav:
            frames = bytearray(wav.readframes(wav.getnframes()))
            
            # Convert data to bits
            bits = ''.join([format(b, '08b') for b in data])
            
            if len(bits) > len(frames):
                raise ValueError("Data too large for this audio file")
            
            # Modify least significant bits
            for i in range(len(bits)):
                frames[i] = (frames[i] & ~1) | int(bits[i])
            
            # Save modified audio
            save_path = filedialog.asksaveasfilename(
                defaultextension=".wav",
                filetypes=[("WAV files", "*.wav")]
            )
            
            if save_path:
                with wave.open(save_path, 'wb') as new_wav:
                    new_wav.setparams(wav.getparams())
                    new_wav.writeframes(frames)
    
    def decode_audio(self, filename: str) -> bytes:
        with wave.open(filename, 'rb') as wav:
            frames = bytearray(wav.readframes(wav.getnframes()))
            
            # Extract bits from least significant bits
            bits = ''.join([str(frame & 1) for frame in frames])
            
            # Convert bits to bytes
            bytes_data = bytearray()
            for i in range(0, len(bits), 8):
                byte = bits[i:i+8]
                if len(byte) == 8:
                    bytes_data.append(int(byte, 2))
            
            return bytes(bytes_data)
    
    def encode_video(self, filename: str, data: bytes):
        cap = cv2.VideoCapture(filename)
        
        # Get video properties
        fps = int(cap.get(cv2.CAP_PROP_FPS))
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        # Convert data to bits
        bits = ''.join([format(b, '08b') for b in data])
        bit_idx = 0
        
        save_path = filedialog.asksaveasfilename(
            defaultextension=".mp4",
            filetypes=[("MP4 files", "*.mp4")]
        )
        
        if save_path:
            out = cv2.VideoWriter(
                save_path,
                cv2.VideoWriter_fourcc(*'mp4v'),
                fps,
                (width, height)
            )
            
            while cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break
                
                # Modify first frame only
                if bit_idx < len(bits):
                    for i in range(height):
                        for j in range(width):
                            for k in range(3):  # RGB channels
                                if bit_idx < len(bits):
                                    # Ensure the pixel value remains within 0-255
                                    new_pixel_value = (frame[i,j,k] & ~1) | int(bits[bit_idx])
                                    frame[i,j,k] = max(0, min(255, new_pixel_value))  # Clamp the value
                                    bit_idx += 1
                
                out.write(frame)
            
            cap.release()
            out.release()
    
    def decode_video(self, filename: str) -> bytes:
        cap = cv2.VideoCapture(filename)
        
        # Read first frame only
        ret, frame = cap.read()
        if not ret:
            raise ValueError("Could not read video file")
        
        height, width = frame.shape[:2]
        bits = ''
        
        # Extract bits from least significant bits
        for i in range(height):
            for j in range(width):
                for k in range(3):  # RGB channels
                    bits += str(frame[i,j,k] & 1)
        
        # Convert bits to bytes
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) == 8:
                bytes_data.append(int(byte, 2))
        
        cap.release()
        return bytes(bytes_data)

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
