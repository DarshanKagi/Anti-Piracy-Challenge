import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from PIL import Image, ImageTk, ImageDraw
from hashlib import sha256
import json
import time
import cv2
import numpy as np
import imagehash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class Watermarker:
    @staticmethod
    def embed_text_dct(host_image, text, alpha=0.5):
        try:
            # Convert to YCbCr color space
            ycbcr = host_image.convert('YCbCr')
            y, cb, cr = ycbcr.split()
            y_array = np.array(y, dtype=np.float32)

            # Create text watermark
            watermark = Image.new('L', (64, 64), 255)
            draw = ImageDraw.Draw(watermark)
            draw.text((10, 25), text, fill=0)
            watermark_array = np.array(watermark).flatten()
            watermark_bits = (watermark_array < 128).astype(np.int8)

            # Process 8x8 blocks
            blocks = []
            for i in range(0, y_array.shape[0], 8):
                for j in range(0, y_array.shape[1], 8):
                    block = y_array[i:i+8, j:j+8]
                    if block.shape == (8, 8):
                        blocks.append(block)

            # Embed watermark bits in DCT coefficients
            for idx, bit in enumerate(watermark_bits):
                if idx >= len(blocks):
                    break
                dct_block = cv2.dct(blocks[idx])
                dct_block[3, 3] = alpha * (100 if bit else -100)
                blocks[idx] = cv2.idct(dct_block)

            # Reconstruct Y channel
            watermarked_y = np.zeros_like(y_array)
            block_idx = 0
            for i in range(0, watermarked_y.shape[0], 8):
                for j in range(0, watermarked_y.shape[1], 8):
                    if block_idx < len(blocks):
                        watermarked_y[i:i+8, j:j+8] = blocks[block_idx]
                        block_idx += 1

            # Merge channels and convert back to RGB
            watermarked_y = np.clip(watermarked_y, 0, 255).astype(np.uint8)
            return Image.merge('YCbCr', (Image.fromarray(watermarked_y), cb, cr)).convert('RGB')
        except Exception as e:
            messagebox.showerror("Error", f"Watermarking failed: {str(e)}")
            return host_image
        
    @staticmethod
    def detect_watermark(watermarked_image, alpha=0.5):
        try:
            # Minimum size check (512x512 pixels for 64x64 watermark)
            if watermarked_image.size[0] < 512 or watermarked_image.size[1] < 512:
                return "Image too small to contain standard watermark (min 512x512 pixels)"

            ycbcr = watermarked_image.convert('YCbCr')
            y, _, _ = ycbcr.split()
            y_array = np.array(y, dtype=np.float32)
            
            watermark_bits = []
            blocks = []
            
            # Extract 8x8 blocks
            for i in range(0, y_array.shape[0], 8):
                for j in range(0, y_array.shape[1], 8):
                    block = y_array[i:i+8, j:j+8]
                    if block.shape == (8, 8):
                        blocks.append(block)
                        if len(blocks) >= 4096:  # Stop when we have enough blocks
                            break
                else:
                    continue
                break
            
            # Extract watermark bits from DCT coefficients
            for block in blocks[:4096]:  # Use exactly 4096 blocks
                dct_block = cv2.dct(block)
                bit_value = dct_block[3, 3] / alpha
                watermark_bits.append(1 if bit_value > 50 else 0)
            
            # Validate we have enough bits
            if len(watermark_bits) != 4096:
                return "No detectable watermark found (invalid block count)"
            
            # Reconstruct watermark image
            watermark_array = np.array(watermark_bits).reshape(64, 64)
            watermark = Image.fromarray((watermark_array * 255).astype(np.uint8))
            
            # Try OCR if available
            try:
                from pytesseract import image_to_string
                text = image_to_string(watermark, config='--psm 6')
                return text.strip() or "Watermark detected but no text recognized"
            except ImportError:
                return "Watermark pattern detected (install pytesseract for text recognition)"
            
        except Exception as e:
            return f"Watermark detection failed: {str(e)}"

    @staticmethod
    def generate_fingerprint(image):
        return str(imagehash.phash(image))

class LSB:
    def encrypt_message(self, msg, password):
        salt = b"fixed_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        iv = b"random_iv_123456"
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(msg.encode()) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_message(self, encrypted_msg, password):
        salt = b"fixed_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        iv = b"random_iv_123456"
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        encrypted_msg_bytes = base64.b64decode(encrypted_msg)
        decrypted = decryptor.update(encrypted_msg_bytes) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        original_msg = unpadder.update(decrypted) + unpadder.finalize()
        return original_msg.decode('utf-8')

    def encode_image(self, img, msg):
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        binary_msg = ''.join(format(ord(c), '08b') for c in msg)
        length = len(binary_msg)
        
        if length > img.width * img.height * 3:
            messagebox.showerror("Error", "Message too long for image capacity!")
            return None
            
        encoded = img.copy()
        pixels = encoded.load()
        index = 0
        
        # Encode message length in first 32 pixels (32 bits)
        length_bin = format(length, '032b')
        for i in range(32):
            x = i % encoded.width
            y = i // encoded.width
            r, g, b = pixels[x, y]
            b = (b & 0xFE) | int(length_bin[i])
            pixels[x, y] = (r, g, b)
        
        # Encode message bits
        for i in range(length):
            x = (i + 32) % encoded.width
            y = (i + 32) // encoded.width
            r, g, b = pixels[x, y]
            channel = i % 3  # Spread across RGB channels
            
            if channel == 0:
                r = (r & 0xFE) | int(binary_msg[i])
            elif channel == 1:
                g = (g & 0xFE) | int(binary_msg[i])
            else:
                b = (b & 0xFE) | int(binary_msg[i])
            
            pixels[x, y] = (r, g, b)
        
        return encoded

    def decode_image(self, img):
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        pixels = img.load()
        binary_length = ''
        
        # Read length from first 32 pixels
        for i in range(32):
            x = i % img.width
            y = i // img.width
            _, _, b = pixels[x, y]
            binary_length += str(b & 1)
        
        length = int(binary_length, 2)
        binary_msg = []
        
        # Read message bits
        for i in range(length):
            x = (i + 32) % img.width
            y = (i + 32) // img.width
            r, g, b = pixels[x, y]
            channel = i % 3
            
            if channel == 0:
                binary_msg.append(str(r & 1))
            elif channel == 1:
                binary_msg.append(str(g & 1))
            else:
                binary_msg.append(str(b & 1))
        
        # Convert binary to string
        msg = ''
        for i in range(0, len(binary_msg), 8):
            byte = binary_msg[i:i+8]
            msg += chr(int(''.join(byte), 2))
        
        return msg
    

class Block:
    def __init__(self, ID, images, timestamp, previousHash):
        self.ID = ID
        self.images = images
        self.timestamp = timestamp
        self.previousHash = previousHash
        self.nonce = 0

    def compute_hash(self):
        block_dict = self.__dict__.copy()
        block_dict['hash'] = "" if not hasattr(self, 'hash') else self.hash
        data = json.dumps(block_dict, sort_keys=True)
        return sha256(data.encode()).hexdigest()

class Blockchain:
    difficulty = 4

    def __init__(self):
        self.chain = []
        self.create_firstBlock()

    def create_firstBlock(self):
        firstBlock = Block(0, [], time.time(), "0")
        firstBlock.hash = firstBlock.compute_hash()
        self.chain.append(firstBlock)

    @property
    def lastBlock(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        previous = self.lastBlock.hash
        if previous != block.previousHash:
            return False
        if not self.is_valid(block, proof):
            return False
        block.hash = proof
        self.chain.append(block)
        return True

    def is_valid(self, block, hashN):
        return (hashN.startswith('0' * Blockchain.difficulty) and hashN == block.compute_hash())

    def pOw(self, block):
        block.nonce = 0
        computedHash = block.compute_hash()
        while not computedHash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computedHash = block.compute_hash()
        return computedHash


class UploadFrame(tk.Frame):
    def __init__(self, master, on_file_selected=None):
        super().__init__(master)
        self.on_file_selected = on_file_selected
        self.watermarked_image = None
        self.configure(bg='#f8f9fa')
        self.create_widgets()

    def create_widgets(self):
        # Upload area
        self.upload_area = tk.Frame(self, bg='white', bd=2, relief='solid')
        self.upload_area.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # Header text
        self.header = tk.Label(
            self.upload_area,
            text="Choose a file or click Browse",
            font=('Arial', 14, 'bold'),
            bg='white'
        )
        self.header.pack(pady=(20, 10))

        # Format info
        self.format_label = tk.Label(
            self.upload_area,
            text="JPEG, PNG formats, up to 50MB",
            font=('Arial', 10),
            fg='#6c757d',
            bg='white'
        )
        self.format_label.pack(pady=(0, 15))

        # Browse button
        self.browse_button = tk.Button(
            self.upload_area,
            text="Browse File",
            command=self.browse_file,
            relief='solid',
            bg='white',
            padx=20,
            pady=5
        )
        self.browse_button.pack(pady=(0, 20))

        # File preview area (initially hidden)
        self.preview_frame = tk.Frame(self, bg='#f8f9fa')
        self.preview_label = tk.Label(self.preview_frame, bg='#f8f9fa')
        self.file_name_label = tk.Label(
            self.preview_frame,
            bg='#f8f9fa',
            font=('Arial', 10)
        )
        self.remove_button = tk.Button(
            self.preview_frame,
            text="✕",
            command=self.remove_file,
            relief='flat',
            bg='#f8f9fa',
            fg='red'
        )

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png *.jpg *.jpeg")]
        )
        if file_path:
            self.handle_file_selection(file_path)

    def handle_file_selection(self, file_path):
        try:
        # Open the original image without modifying it
            original_image = Image.open(file_path)
        
        # Create a thumbnail copy for preview
            thumbnail_image = original_image.copy()
            thumbnail_image.thumbnail((200, 200))
            photo = ImageTk.PhotoImage(thumbnail_image)
        
        # Update preview elements with thumbnail
            self.preview_label.config(image=photo)
            self.preview_label.image = photo
            self.file_name_label.config(text=file_path.split('/')[-1])
        
        # Arrange preview elements
            self.preview_frame.pack(pady=10)
            self.file_name_label.pack(side=tk.LEFT, padx=5)
            self.preview_label.pack(side=tk.LEFT, padx=5)
            self.remove_button.pack(side=tk.LEFT, padx=5)
        
        # Pass the original image to the callback
            if self.on_file_selected:
                self.on_file_selected(original_image, file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open image: {str(e)}")

    def remove_file(self):  # ADDED MISSING METHOD
        # Clear preview
        self.preview_label.config(image='')
        self.file_name_label.config(text='')
        self.preview_frame.pack_forget()
        
        # Notify parent
        if self.on_file_selected:
            self.on_file_selected(None, None)
        
        self.watermarked_image = None

    # Rest of the UploadFrame methods remain the same...
class BlockchainApp:
    def __init__(self, root):
        self.blockchain = Blockchain()
        self.lsb = LSB()
        self.watermarker = Watermarker()
        self.root = root
        self.root.title("Blockchain Content Protection")
        self.create_widgets()

    def create_widgets(self):
        # Main frame
        self.frame = tk.Frame(self.root)
        self.frame.pack(pady=10)

        # Upload frame with enhanced preview
        self.upload_frame = UploadFrame(
            self.root,
            on_file_selected=self.handle_image_selected
        )
        self.upload_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Action buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        buttons = [
            ("Encode Message", self.encode_message),
            ("Decode Message", self.decode_message),
            ("Add Watermark", self.save_watermark),
            ("Mine Block", self.mine_block),
            ("View Chain", self.view_chain)
        ]
        
        for text, cmd in buttons:
            tk.Button(button_frame, text=text, command=cmd).pack(side=tk.LEFT, padx=5)

    def handle_image_selected(self, image, file_path):
        if image:
            self.image = image
            self.fingerprint = self.watermarker.generate_fingerprint(image)
        else:
            if hasattr(self, 'image'):
                del self.image
            if hasattr(self, 'fingerprint'):
                del self.fingerprint

    def save_watermark(self):
        # Case 2: Handle when no image is uploaded
        if not hasattr(self, 'image') or self.image is None:
            messagebox.showerror("Error", "Please upload an image first.")
            return

        # Get watermark text from user
        watermark_text = simpledialog.askstring("Watermark Text", 
                                              "Enter text for watermark:")
        if not watermark_text:
            return  # User canceled

        try:
            # Case 1: Generate actual watermarked image
            self.upload_frame.watermarked_image = self.watermarker.embed_text_dct(
                self.image, 
                watermark_text
            )

            # Get save path with overwrite confirmation
            save_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png")],
                confirmoverwrite=True  # Add native overwrite protection
            )
            
            if save_path:
                # Handle existing file check manually for better control
                if os.path.exists(save_path):
                    if not messagebox.askyesno("Confirm", f"{os.path.basename(save_path)} exists. Overwrite?"):
                        return
                
                self.upload_frame.watermarked_image.save(save_path)
                messagebox.showinfo("Success", "Watermarked image saved!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create watermark: {str(e)}")

    def encode_message(self):
        if not hasattr(self, 'image'):
            messagebox.showerror("Error", "Please upload an image first.")
            return
        msg = simpledialog.askstring("Message", "Enter the message to encode:")
        if msg:
            # Custom password dialog
            password_window = tk.Toplevel(self.root)
            password_window.title("Password")
            password_window.geometry("300x150")
            password_window.grab_set()  # Make the window modal

            label = tk.Label(password_window, text="Enter password for encryption:")
            label.pack(pady=10)

            password_entry = tk.Entry(password_window, show="*")
            password_entry.pack(pady=10)
            password_entry.focus_set()

            def on_submit():
                password = password_entry.get()
                if password:
                    encrypted_msg = self.lsb.encrypt_message(msg, password)
                    encoded_image = self.lsb.encode_image(self.image, encrypted_msg)
                    if encoded_image:
                        save_path = filedialog.asksaveasfilename(
                            defaultextension=".png",
                            filetypes=[("PNG files", "*.png")]
                        )
                        if save_path:
                            encoded_image.save(save_path)
                            messagebox.showinfo("Success", "Message encoded and saved!")
                        password_window.destroy()  # Close the password window
                    else:
                        messagebox.showerror("Error", "Failed to encode the image")
                        password_window.destroy()  # Close the password window
                else:
                    messagebox.showerror("Error", "Password cannot be empty")

            submit_btn = tk.Button(password_window, text="Submit", command=on_submit)
            submit_btn.pack(pady=10)

    def decode_message(self):
        if not hasattr(self, 'image'):
            messagebox.showerror("Error", "Please upload an image first.")
            return
        encrypted_msg = self.lsb.decode_image(self.image)
        password = simpledialog.askstring("Password", "Enter password to decrypt:")
        if password:
            try:
                msg = self.lsb.decrypt_message(encrypted_msg, password)
                messagebox.showinfo("Decoded Message", msg)
            except Exception as e:
                messagebox.showerror("Error", "Invalid password or corrupted message")

    def mine_block(self):
        if not hasattr(self, 'fingerprint'):
            messagebox.showwarning("Warning", "No content fingerprint available")
            return

        new_block = Block(
            ID=len(self.blockchain.chain),
            images=[self.fingerprint],
            timestamp=time.time(),
            previousHash=self.blockchain.lastBlock.hash
        )
        proof = self.blockchain.pOw(new_block)
        if self.blockchain.add_block(new_block, proof):
            messagebox.showinfo("Success", "Block mined with content fingerprint!")
        else:
            messagebox.showerror("Error", "Block mining failed")

    def view_chain(self):
        chain_data = json.dumps([block.__dict__ for block in self.blockchain.chain], indent=4)
        top = tk.Toplevel(self.root)
        top.title("Blockchain")
        text = tk.Text(top, wrap=tk.WORD)
        text.insert(tk.END, chain_data)
        text.pack(expand=True, fill=tk.BOTH)

    # Existing encode/decode/view_chain methods remain unchanged
    # ... [Previous BlockchainApp methods] ...

if __name__ == "__main__":
    root = tk.Tk()
    app = BlockchainApp(root)
    root.mainloop()