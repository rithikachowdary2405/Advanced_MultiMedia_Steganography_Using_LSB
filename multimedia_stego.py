import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import wave, os, hashlib, base64, smtplib,qrcode,time
from cryptography.fernet import Fernet
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
from tkinter import ttk



otp_timestamp = None
OTP_EXPIRY_SECONDS = 120

current_otp = None
generated_password = None

def generate_fernet_key_from_password(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())


def encrypt_message(password, message):
    f = Fernet(generate_fernet_key_from_password(password))

    if isinstance(message, bytes):
        return f.encrypt(message)
    else:
        return f.encrypt(message.encode())

def decrypt_message(password, token):
    return Fernet(generate_fernet_key_from_password(password)).decrypt(token).decode()


def enforce_16_chars(entry):
    def limit(_):
        if len(entry.get()) > 16:
            entry.delete(16, tk.END)
    entry.bind("<KeyRelease>", limit)


def bytes_to_bits(data):
    for b in data:
        for i in range(7, -1, -1):
            yield (b >> i) & 1


def bits_to_bytes(bits):
    b, out, count = 0, bytearray(), 0
    for bit in bits:
        b = (b << 1) | bit
        count += 1
        if count == 8:
            out.append(b)
            b = 0
            count = 0
    return bytes(out)


def embed_message(input_wav, output_wav, message_bytes):
    with wave.open(input_wav, 'rb') as wf:
        params = wf.getparams()
        frames = bytearray(wf.readframes(wf.getnframes()))
    header = len(message_bytes).to_bytes(4, 'big')
    data = header + message_bytes
    bits = list(bytes_to_bits(data))
    if len(bits) > len(frames):
        raise ValueError("Message too large")
    for i, bit in enumerate(bits):
        frames[i] = (frames[i] & 0xFE) | bit
    with wave.open(output_wav, 'wb') as wf:
        wf.setparams(params)
        wf.writeframes(bytes(frames))


def extract_message(input_wav):
    with wave.open(input_wav, 'rb') as wf:
        frames = bytearray(wf.readframes(wf.getnframes()))
    bits = [frames[i] & 1 for i in range(32)]
    msg_len = int.from_bytes(bits_to_bytes(bits), 'big')
    bits = [frames[i] & 1 for i in range(32, 32 + msg_len * 8)]
    return bits_to_bytes(bits)


def embed_image_message(input_img, output_img, message_bytes):
    img = Image.open(input_img).convert("RGB")
    pixels = list(img.getdata())
    header = len(message_bytes).to_bytes(4, 'big')
    data = header + message_bytes
    bits = list(bytes_to_bits(data))
    if len(bits) > len(pixels) * 3:
        raise ValueError("Message too large")
    new_pixels, idx = [], 0
    for r, g, b in pixels:
        if idx < len(bits): r = (r & 0xFE) | bits[idx]; idx += 1
        if idx < len(bits): g = (g & 0xFE) | bits[idx]; idx += 1
        if idx < len(bits): b = (b & 0xFE) | bits[idx]; idx += 1
        new_pixels.append((r, g, b))
    img.putdata(new_pixels)
    img.save(output_img)


def extract_image_message(input_img):
    img = Image.open(input_img).convert("RGB")
    pixels = list(img.getdata())
    bits = []
    for r, g, b in pixels:
        bits.extend([r & 1, g & 1, b & 1])
    msg_len = int.from_bytes(bits_to_bytes(bits[:32]), 'big')
    return bits_to_bytes(bits[32:32 + msg_len * 8])



def embed_file_in_image(input_img, output_img, file_path, password):

    img = Image.open(input_img).convert("RGB")
    pixels = list(img.getdata())

    filename = os.path.basename(file_path).encode()

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    encrypted_bytes = encrypt_message(password, file_bytes)

    filename_len = len(filename).to_bytes(2, 'big')
    header = filename_len + filename + encrypted_bytes

    data_len = len(header).to_bytes(4, 'big')
    data = data_len + header

    bits = list(bytes_to_bits(data))

    if len(bits) > len(pixels) * 3:
        raise ValueError("File too large for this image")

    new_pixels = []
    idx = 0

    for r, g, b in pixels:

        if idx < len(bits):
            r = (r & 0xFE) | bits[idx]; idx += 1
        if idx < len(bits):
            g = (g & 0xFE) | bits[idx]; idx += 1
        if idx < len(bits):
            b = (b & 0xFE) | bits[idx]; idx += 1

        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_img)
    
def extract_file_from_image(input_img, password, save_path):

    img = Image.open(input_img).convert("RGB")
    pixels = list(img.getdata())

    bits = []

    for r, g, b in pixels:
        bits.extend([r & 1, g & 1, b & 1])

    data_len = int.from_bytes(bits_to_bytes(bits[:32]), 'big')

    data = bits_to_bytes(bits[32:32 + data_len * 8])

    filename_len = int.from_bytes(data[:2], 'big')

    filename = data[2:2 + filename_len].decode()

    encrypted_data = data[2 + filename_len:]

    file_bytes = Fernet(generate_fernet_key_from_password(password)).decrypt(encrypted_data)

    with open(save_path, "wb") as f:
        f.write(file_bytes)

    return save_path

def detect_image_steganography(image_path):
    try:
        img = Image.open(image_path).convert("RGB")
        pixels = list(img.getdata())

        bits = []
        for r, g, b in pixels[:1000]:  
            bits.extend([r & 1, g & 1, b & 1])

        ones = sum(bits)
        zeros = len(bits) - ones

        ratio = ones / len(bits)

        if 0.48 < ratio < 0.50:
            return "⚠ Suspicious: Possible Hidden Data"
       
        else:
            return "✅ No Strong Evidence of Steganography"

    except Exception as e:
        return f"Error: {str(e)}"
    
def detect_audio_steganography(audio_path):
    try:
        with wave.open(audio_path, 'rb') as wf:
            frames = bytearray(wf.readframes(wf.getnframes()))

        bits = [frames[i] & 1 for i in range(32)]
        msg_len = int.from_bytes(bits_to_bytes(bits), 'big')

        max_possible = len(frames) // 8  

        if msg_len > 0 and msg_len < max_possible:
            return "⚠ Hidden Data Detected (Valid Header Found)"
        else:
            return "✅ Audio seems normal"

    except wave.Error:
        return "❌ Please select a valid WAV audio file"

    except Exception as e:
        return f"Error: {str(e)}"
    
def detect_steganography_ui():
    clear()

    tk.Label(root, image=bg_feature).place(relwidth=1, relheight=1)

    tk.Label(
        root,
        text="STEGANOGRAPHY DETECTOR",
        fg="#16a3da",
        bg="#0a0f1e",
        font=heading_font
    ).pack(pady=40)

    f = tk.Frame(root, bg="#111827")
    f.pack(pady=20)

    file_type = tk.StringVar(value="image")

    tk.Radiobutton(f, text="Image", variable=file_type, value="image",
               bg="#111827", fg="white", selectcolor="#111827").grid(row=1, column=0)

    tk.Radiobutton(f, text="Audio", variable=file_type, value="audio",
               bg="#111827", fg="white", selectcolor="#111827").grid(row=1, column=1)

    file_path = tk.Entry(f, width=60)

    tk.Label(f, text="Select File", bg="#111827", fg="white",
             font=("Consolas", 16)).grid(row=0, column=0)

    file_path.grid(row=0, column=1)

    def browse():
        path = filedialog.askopenfilename(
            filetypes=[("Media Files", "*.wav *.png *.jpg *.jpeg")]
        )
        if path:
            file_path.delete(0, tk.END)
            file_path.insert(0, path)

    tk.Button(f, text="Browse", command=browse).grid(row=0, column=2)

    result_box = tk.Text(root, width=80, height=10)
    result_box.pack(pady=20)

    def detect():
        path = file_path.get()

        if not path:
            messagebox.showerror("Error", "Please select a file")
            return

        if file_type.get() == "audio":
            if not path.lower().endswith(".wav"):
                messagebox.showerror("Error", "Please select a WAV audio file")
                return
            result = detect_audio_steganography(path)

        elif file_type.get() == "image":
            if not path.lower().endswith((".png", ".jpg", ".jpeg")):
                messagebox.showerror("Error", "Please select an image file")
                return
            result = detect_image_steganography(path)

        else:
            result = "Unsupported selection"

        result_box.delete("1.0", tk.END)
        result_box.insert(tk.END, result)

    tk.Button(root, text="Detect", font=cyber_font,
              bg="#16a3da", command=detect).pack(pady=10)

    tk.Button(root, text="Back", font=cyber_font,
              bg="#16a3da", command=menu).pack()


def browse_file(e):
    p = filedialog.askopenfilename(filetypes=[("WAV", "*.wav")])
    if p: e.delete(0, tk.END); e.insert(0, p)


def save_file(e):
    p = filedialog.asksaveasfilename(defaultextension=".wav")
    if p: e.delete(0, tk.END); e.insert(0, p)


def browse_image(e):
    p = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg")])
    if p: e.delete(0, tk.END); e.insert(0, p)


def save_image(e):
    p = filedialog.asksaveasfilename(defaultextension=".png")
    if p: e.delete(0, tk.END); e.insert(0, p)


root = tk.Tk()
root.state("zoomed")
root.title("StegoVault")

sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
bg_start = ImageTk.PhotoImage(Image.open("images/robo_open.jpg").resize((sw, sh)))
bg_main = ImageTk.PhotoImage(Image.open("images/boyhacker.jpeg").resize((sw, sh)))
bg_feature = ImageTk.PhotoImage(Image.open("images/hackroom.jpeg").resize((sw, sh)))

cyber_font = ("Consolas", 18, "bold")
heading_font = ("Consolas", 36, "bold")


def clear():
    for w in root.winfo_children():
        w.destroy()


def welcome():
    clear()
    tk.Label(root, image=bg_start).place(relwidth=1, relheight=1)
    tk.Label(root, text="STEGOVAULT", fg="#001aff", bg="#060606", font=heading_font).pack(pady=120)
    tk.Button(root, text="ENTER VAULT", font=cyber_font, bg="#00ffcc", command=menu).pack(pady=50)


def menu():

    clear()

    tk.Label(root, image=bg_main).place(relwidth=1, relheight=1)

    tk.Label(
        root,
        text="STEGOVAULT",
        fg="#00ff26",
        bg="#0a0f1e",
        font=heading_font
    ).pack(pady=40)

    frame = tk.Frame(root, bg="#0a0f1e")
    frame.pack(pady=40)

    # Bigger Combobox Style
    style = ttk.Style()
    style.configure("TCombobox", font=("Consolas", 15))

    root.option_add("*TCombobox*Listbox.font", ("Consolas", 15))

    # MODULE LABEL
    tk.Label(
        frame,
        text="Select Module",
        bg="#0a0f1e",
        fg="white",
        font=("Consolas", 20, "bold")
    ).pack(pady=10)

    # MODULE DROPDOWN
    module = ttk.Combobox(
    frame,
    values=[
    "Audio Steganography",
    "Image Steganography",
    "Text File in Image Steganography",
    "Steganography Detector",
    "Secure Media Transfer",
    "OTP Verification"
    ],
        width=40,
        state="readonly"
    )

    module.pack(pady=15)

    # ACTION LABEL
    action_label = tk.Label(
        frame,
        text="Select Action",
        bg="#0a0f1e",
        fg="white",
        font=("Consolas", 15, "bold")
    )

    action_label.pack(pady=10)

    # ACTION DROPDOWN
    action = ttk.Combobox(
        frame,
        values=["Encrypt", "Decrypt"],
        width=40,
        state="readonly"
    )

    action.pack(pady=15)

    # Hide Action dropdown when Secure Media Transfer selected
    def module_changed(event):

      if module.get() in ["Secure Media Transfer", "Steganography Detector", "OTP Verification"]:

        action_label.pack_forget()
        action.pack_forget()

      else:

        action_label.pack(pady=10)
        action.pack(pady=15)

    module.bind("<<ComboboxSelected>>", module_changed)

    # Open selected module
    def open_module():

        m = module.get()
        a = action.get()

        if m == "Audio Steganography" and a == "Encrypt":
            hide_audio()

        elif m == "Audio Steganography" and a == "Decrypt":
            decode_audio()

        elif m == "Image Steganography" and a == "Encrypt":
            hide_image()

        elif m == "Image Steganography" and a == "Decrypt":
            decode_image()

        elif m == "Text File in Image Steganography" and a == "Encrypt":
            hide_file_image()

        elif m == "Text File in Image Steganography" and a == "Decrypt":
            decode_file_image()

        elif m == "Steganography Detector":
            detect_steganography_ui()
        
        elif m == "Secure Media Transfer":
            secure_courier()
            
        elif m == "OTP Verification":
            otp_verification_ui()

        

        else:
            messagebox.showerror("Error", "Please select module and action")

    # OPEN BUTTON
    tk.Button(
        root,
        text="Open Module",
        font=("Consolas", 20, "bold"),
        bg="#16a3da",
        width=18,
        command=open_module
    ).pack(pady=30)

    # BACK BUTTON
    tk.Button(
        root,
        text="Back",
        font=("Consolas", 20, "bold"),
        bg="#16a3da",
        width=18,
        command=welcome
    ).pack()

def hide_audio():
    clear()
    tk.Label(root, image=bg_feature).place(relwidth=1, relheight=1)
    tk.Label(root, text="AUDIO ENCRYPTOR", fg="#16a3da", bg="#0a0f1e", font=heading_font).pack(pady=40)

    f = tk.Frame(root, bg="#111827"); f.pack(pady=20)
    e1 = tk.Entry(f, width=60); e2 = tk.Entry(f, width=60)
    e3 = tk.Entry(f, width=60); k = tk.Entry(f, width=60, show="*")
    enforce_16_chars(k)

    tk.Label(f, text="Input WAV", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=0, column=0)
    e1.grid(row=0, column=1); 
    tk.Button(f,text="Browse",command=lambda: browse_file(e1),font=("Consolas", 10, "bold"), width=6,height=0).grid(row=0, column=2)

    tk.Label(f, text="Output WAV", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=1, column=0)
    e2.grid(row=1, column=1); tk.Button(f, text="Save", command=lambda: save_file(e2),font=("Consolas", 10, "bold"), width=6,height=0).grid(row=1, column=2)

    tk.Label(f, text="Message", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=2, column=0)
    e3.grid(row=2, column=1)

    tk.Label(f, text="Password (16 chars)", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=3, column=0)
    k.grid(row=3, column=1)

    def run():
        if len(k.get()) != 16:
            messagebox.showerror("Error", "Password must be atleast 16 characters")
            return
        data = encrypt_message(k.get(), e3.get())
        embed_message(e1.get(), e2.get(), data)
        messagebox.showinfo("Done", "Message hidden")

    tk.Button(root, text="Encrypt & Hide", font=cyber_font, bg="#16a3da", command=run).pack(pady=20)
    tk.Button(root, text="Back", font=cyber_font, bg="#16a3da",
              width=18, height=1, command=menu).pack()


def decode_audio():
    clear()
    tk.Label(root, image=bg_feature).place(relwidth=1, relheight=1)
    tk.Label(root, text="AUDIO DECODER", fg="#16a3da", bg="#0a0f1e", font=heading_font).pack(pady=40)

    f = tk.Frame(root, bg="#111827"); f.pack(pady=20)
    e = tk.Entry(f, width=60); k = tk.Entry(f, width=60, show="*")
    enforce_16_chars(k)

    tk.Label(f, text="Stego WAV", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=0, column=0)
    e.grid(row=0, column=1); tk.Button(f, text="Browse", command=lambda: browse_file(e)).grid(row=0, column=2)

    tk.Label(f, text="Password (16 chars)", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=1, column=0)
    k.grid(row=1, column=1)

    out = tk.Text(root, width=100, height=15); out.pack(pady=20)

    def run():
        if len(k.get()) != 16:
            out.delete("1.0", tk.END)
            out.insert(tk.END, "Password must be atleast 16 characters")
            return
        try:
            data = extract_message(e.get())
            text = decrypt_message(k.get(), data)
        except:
            text = "Invalid password or corrupted file"
        out.delete("1.0", tk.END)
        out.insert(tk.END, text)

    tk.Button(root, text="Extract", font=cyber_font, bg="#16a3da",width=10, height=1, command=run).pack()
    tk.Button(root, text="Back", font=cyber_font, bg="#16a3da",
              width=10, height=1, command=menu).pack()


def hide_image():
    clear()
    tk.Label(root, image=bg_feature).place(relwidth=1, relheight=1)
    tk.Label(root, text="IMAGE ENCRYPTOR", fg="#16a3da", bg="#0a0f1e", font=heading_font).pack(pady=40)

    f = tk.Frame(root, bg="#111827"); f.pack(pady=20)
    i = tk.Entry(f, width=60); o = tk.Entry(f, width=60)
    m = tk.Entry(f, width=60); k = tk.Entry(f, width=60, show="*")
    enforce_16_chars(k)

    tk.Label(f, text="Input Image", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=0, column=0)
    i.grid(row=0, column=1); tk.Button(f, text="Browse", command=lambda: browse_image(i)).grid(row=0, column=2)

    tk.Label(f, text="Output Image", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=1, column=0)
    o.grid(row=1, column=1); tk.Button(f, text="Save", command=lambda: save_image(o)).grid(row=1, column=2)

    tk.Label(f, text="Message", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=2, column=0)
    m.grid(row=2, column=1)

    tk.Label(f, text="Password (16 chars)", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=3, column=0)
    k.grid(row=3, column=1)

    def run():
        if len(k.get()) != 16:
            messagebox.showerror("Error", "Password must be atleast 16 characters")
            return
        data = encrypt_message(k.get(), m.get())
        embed_image_message(i.get(), o.get(), data)
        messagebox.showinfo("Done", "Message hidden in image")

    tk.Button(root, text="Encrypt Image", font=cyber_font, bg="#16a3da", command=run).pack(pady=20)
    tk.Button(root, text="Back", font=cyber_font, bg="#16a3da",
              width=18, height=1, command=menu).pack()


def decode_image():
    clear()
    tk.Label(root, image=bg_feature).place(relwidth=1, relheight=1)
    tk.Label(root, text="IMAGE DECODER", fg="#16a3da", bg="#0a0f1e", font=heading_font).pack(pady=40)

    f = tk.Frame(root, bg="#111827"); f.pack(pady=20)
    i = tk.Entry(f, width=60); k = tk.Entry(f, width=60, show="*")
    enforce_16_chars(k)

    tk.Label(f, text="Stego Image", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=0, column=0)
    i.grid(row=0, column=1); tk.Button(f, text="Browse", command=lambda: browse_image(i)).grid(row=0, column=2)

    tk.Label(f, text="Password (16 chars)", bg="#111827", fg="white",font=("Consolas", 16)).grid(row=1, column=0)
    k.grid(row=1, column=1)

    out = tk.Text(root, width=100, height=15); out.pack(pady=20)

    def run():
        if len(k.get()) != 16:
            out.delete("1.0", tk.END)
            out.insert(tk.END, "Password must be atleast 16 characters")
            return
        try:
            data = extract_image_message(i.get())
            text = decrypt_message(k.get(), data)
        except:
            text = "Invalid password or corrupted image"
        out.delete("1.0", tk.END)
        out.insert(tk.END, text)

    tk.Button(root, text="Extract Message", font=cyber_font, bg="#16a3da", command=run).pack()
    tk.Button(root, text="Back", font=cyber_font, bg="#16a3da",
              width=18, height=1, command=menu).pack()
    
def hide_file_image():
    clear()
    tk.Label(root, image=bg_feature).place(relwidth=1, relheight=1)
    tk.Label(root, text=" TEXT FILE → IMAGE ENCRYPTOR",
             fg="#16a3da", bg="#0a0f1e", font=heading_font).pack(pady=40)

    f = tk.Frame(root, bg="#111827"); f.pack(pady=20)

    i = tk.Entry(f, width=60)
    o = tk.Entry(f, width=60)
    file_entry = tk.Entry(f, width=60)
    k = tk.Entry(f, width=60, show="*")

    enforce_16_chars(k)

    tk.Label(f, text="Input Image", bg="#111827", fg="white",
             font=("Consolas", 16)).grid(row=0, column=0)
    i.grid(row=0, column=1)
    tk.Button(f, text="Browse", command=lambda: browse_image(i)).grid(row=0, column=2)

    tk.Label(f, text="Output Image", bg="#111827", fg="white",
             font=("Consolas", 16)).grid(row=1, column=0)
    o.grid(row=1, column=1)
    tk.Button(f, text="Save", command=lambda: save_image(o)).grid(row=1, column=2)

    tk.Label(f, text="Secret File", bg="#111827", fg="white",
             font=("Consolas", 16)).grid(row=2, column=0)
    file_entry.grid(row=2, column=1)

    tk.Button(
    f,
      text="Browse",
      command=lambda: file_entry.delete(0, tk.END) or file_entry.insert(
      0, 
      filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
      )
    ).grid(row=2, column=2)

    tk.Label(f, text="Password (16 chars)", bg="#111827", fg="white",
             font=("Consolas", 16)).grid(row=3, column=0)

    k.grid(row=3, column=1)

    def run():
        if len(k.get()) != 16:
            messagebox.showerror("Error", "Password must be atleast 16 characters")
            return

    # Allow only .txt files
        if not file_entry.get().lower().endswith(".txt"):
            messagebox.showerror("Error", "Only .txt files can be hidden inside the image.")
            return

        try:
            embed_file_in_image(i.get(), o.get(), file_entry.get(), k.get())
            messagebox.showinfo("Done", "File hidden inside image")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    tk.Button(root, text="Encrypt File", font=cyber_font,
              bg="#16a3da", command=run).pack(pady=20)

    tk.Button(root, text="Back", font=cyber_font,
              bg="#16a3da", width=18, height=1, command=menu).pack()
    
def decode_file_image():
    clear()
    tk.Label(root, image=bg_feature).place(relwidth=1, relheight=1)

    tk.Label(root, text="TEXT FILE → IMAGE DECODER",
             fg="#16a3da", bg="#0a0f1e", font=heading_font).pack(pady=40)

    f = tk.Frame(root, bg="#111827"); f.pack(pady=20)

    i = tk.Entry(f, width=60)
    o = tk.Entry(f, width=60)
    k = tk.Entry(f, width=60, show="*")

    enforce_16_chars(k)

    tk.Label(f, text="Stego Image", bg="#111827", fg="white",
             font=("Consolas", 16)).grid(row=0, column=0)

    i.grid(row=0, column=1)
    tk.Button(f, text="Browse", command=lambda: browse_image(i)).grid(row=0, column=2)

    tk.Label(f, text="Save File", bg="#111827", fg="white",
             font=("Consolas", 16)).grid(row=1, column=0)

    o.grid(row=1, column=1)
    tk.Button(f, text="Save",
              command=lambda: o.insert(0, filedialog.asksaveasfilename())
              ).grid(row=1, column=2)

    tk.Label(f, text="Password (16 chars)", bg="#111827", fg="white",
             font=("Consolas", 16)).grid(row=2, column=0)

    k.grid(row=2, column=1)

    def run():

        if len(k.get()) != 16:
            messagebox.showerror("Error", "Password must be atleast 16 characters")
            return

        try:
            filename = extract_file_from_image(i.get(), k.get(), o.get())
            messagebox.showinfo("Done", f"File extracted as {filename}")
        except:
            messagebox.showerror("Error", "Invalid password or corrupted image")

    tk.Button(root, text="Extract File", font=cyber_font,
              bg="#16a3da", command=run).pack(pady=20)

    tk.Button(root, text="Back", font=cyber_font,
              bg="#16a3da", width=18, height=1, command=menu).pack()

import random

def generate_otp():
    return str(random.randint(100000, 999999))
    
def secure_courier():
    clear()
    tk.Label(root, image=bg_feature).place(relwidth=1, relheight=1)

    tk.Label(
        root,
        text="SECURE MEDIA TRANSFER",
        fg="#16a3da",
        bg="#0a0f1e",
        font=heading_font
    ).pack(pady=30)

    f = tk.Frame(root, bg="#111827")
    f.pack(pady=15)

    file_type = tk.StringVar(value="audio")

    tk.Label(f, text="Select File Type", bg="#111827", fg="white",font = ("Consolas",14)).grid(row=0, column=0,sticky = "w")
    tk.Radiobutton(f, text="Audio", variable=file_type, value="audio",
                   bg="#111827", fg="white", selectcolor="#111827",font = ("Consolas",14)).grid(row=0, column=1,sticky = "w")
    tk.Radiobutton(f, text="Image", variable=file_type, value="image",
                   bg="#111827", fg="white", selectcolor="#111827",font = ("Consolas",14)).grid(row=0, column=2,sticky = "w")

    labels = ["Sender Email", "App Password", "Receiver Email", "Subject", "Message", "Stego File"]

    entries = []

    for i, text in enumerate(labels, start=1):
        tk.Label(f, text=text, bg="#111827", fg="white",font = ("Consolas",14)).grid(row=i, column=0)
        e = tk.Entry(f, width=55, show="*" if "Password" in text else None)
        e.grid(row=i, column=1)
        entries.append(e)

        if "Stego File" in text:
            def browse():
                if file_type.get() == "audio":
                    path = filedialog.askopenfilename(filetypes=[("WAV", "*.wav")])
                else:
                    path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg")])
                if path:
                    e.delete(0, tk.END)
                    e.insert(0, path)

            tk.Button(f, text="Browse", command=browse).grid(row=i, column=2)

    def send():
        global current_otp, generated_password

        try:
            sender = entries[0].get()
            app_pass = entries[1].get()
            receiver = entries[2].get()
            subject = entries[3].get()
            body = entries[4].get()
            filepath = entries[5].get()

            otp = generate_otp()
            current_otp = otp

            global otp_timestamp
            

            password_window = tk.Toplevel(root)
            password_window.title("Set Password")

            tk.Label(password_window, text="Enter Password (16 chars)").pack(pady=10)
            pwd_entry = tk.Entry(password_window, show="*", width=30)
            pwd_entry.pack(pady=10)

            def confirm_password():
                global generated_password

                try:
                    pwd = pwd_entry.get()
                    if len(pwd) != 16:
                        messagebox.showerror("Error", "Password must be 16 characters")
                        return

                    generated_password = pwd
                    password_window.destroy()

                    encrypted_pwd = encrypt_message(otp, generated_password).decode()

                    qr = qrcode.make(encrypted_pwd)
                    qr_path = "secure_qr.png"
                    qr.save(qr_path)

                    msg = MIMEMultipart()
                    msg["From"] = sender
                    msg["To"] = receiver
                    msg["Subject"] = subject

                    full_body = f"{body}\n\nYour OTP is: {otp}\n\nScan attached QR for a gift"
                    msg.attach(MIMEText(full_body, "plain"))

                    with open(filepath, "rb") as file:
                        part = MIMEBase("application", "octet-stream")
                        part.set_payload(file.read())

                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(filepath)}")
                    msg.attach(part)

                    with open(qr_path, "rb") as f:
                        part = MIMEBase("application", "octet-stream")
                        part.set_payload(f.read())

                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", "attachment; filename=secure_qr.png")
                    msg.attach(part)

                    with smtplib.SMTP("smtp.gmail.com", 587) as server:
                        server.starttls()
                        server.login(sender, app_pass)
                        server.send_message(msg)

                    messagebox.showinfo("Mail sent successfully!")
                    #otp_verification_ui()

                except Exception as e:
                    messagebox.showerror("Error", str(e))

            tk.Button(password_window, text="Confirm", command=confirm_password).pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
        
    tk.Button(root, text="Send Secure Mail", font=cyber_font, bg="#16a3da", command=send).pack(pady=15)

    tk.Button(root, text="Back", font=cyber_font, bg="#16a3da", command=menu).pack(pady=10)



def otp_verification_ui():
    global otp_timestamp
    otp_timestamp = time.time()
    clear()

    tk.Label(root, image=bg_feature).place(relwidth=1, relheight=1)

    tk.Label(
        root,
        text="OTP VERIFICATION",
        fg="#16a3da",
        bg="#0a0f1e",
        font=heading_font
    ).pack(pady=40)

    frame = tk.Frame(root, bg="#111827")
    frame.pack(pady=30)

    tk.Label(
        frame,
        text="Enter OTP",
        bg="#111827",
        fg="white",
        font=("Consolas", 16)
    ).grid(row=0, column=0, pady=10)

    otp_entry = tk.Entry(frame, width=30)
    otp_entry.grid(row=0, column=1, pady=10)

    result = tk.Label(
        root,
        text="",
        bg="#0a0f1e",
        fg="white",
        font=("Consolas", 14)
    )
    result.pack(pady=10)

    # ⏳ TIMER LABEL
    timer_label = tk.Label(
        root,
        text="",
        bg="#0a0f1e",
        fg="yellow",
        font=("Consolas", 14)
    )
    timer_label.pack()

    def update_timer():
        if otp_timestamp:
            remaining = OTP_EXPIRY_SECONDS - int(time.time() - otp_timestamp)

            if remaining > 0:
                timer_label.config(text=f"⏳ OTP expires in: {remaining} sec")
                root.after(1000, update_timer)
            else:
                timer_label.config(text="❌ OTP expired")

    update_timer()

    def verify():
        entered_otp = otp_entry.get()

        enc_window = tk.Toplevel(root)
        enc_window.title("Enter Encrypted Password")

        tk.Label(enc_window, text="Paste Encrypted Password").pack(pady=10)
        enc_entry = tk.Entry(enc_window, width=50)
        enc_entry.pack(pady=10)

        def decrypt_pwd():
            try:
                current_time = time.time()

                # ⏳ Expiry check
                if current_time - otp_timestamp > OTP_EXPIRY_SECONDS:
                    result.config(text="⏳ OTP Expired!", fg="orange")
                    return

                # ❌ Wrong OTP
                if entered_otp != current_otp:
                    result.config(text="❌ Invalid OTP", fg="red")
                    return

                # ✅ Correct → decrypt
                decrypted = decrypt_message(entered_otp, enc_entry.get().encode())
                result.config(text=f"✅ Password: {decrypted}", fg="lightgreen")
                enc_window.destroy()

            except:
                result.config(text="❌ Decryption Failed", fg="red")

        tk.Button(enc_window, text="Decrypt", command=decrypt_pwd).pack(pady=10)

    tk.Button(
        root,
        text="Verify OTP",
        font=("Consolas", 16, "bold"),
        bg="#16a3da",
        width=18,
        command=verify
    ).pack(pady=20)

    tk.Button(
        root,
        text="Back",
        font=("Consolas", 16, "bold"),
        bg="#16a3da",
        width=18,
        command=menu
    ).pack()
   

welcome()
root.mainloop()