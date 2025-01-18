import tkinter as tk
from tkinter import scrolledtext
import random
import string

def generate_password(entry_password, entry_pass_length):
    try:
        length = int(entry_pass_length.get())  # Longitud de la contraseña
        if (length < 7 or length > 25):
            entry_password.delete(0, tk.END)
            return entry_password.insert(tk.END, "La longitud debe ser entre 7 y 25")
    except:
        entry_password.delete(0, tk.END)
        return entry_password.insert(tk.END, "La longitud de la contraseña no es valida")
    caracteres = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(caracteres) for _ in range(length))
    entry_password.delete(0, tk.END)
    entry_password.insert(tk.END, password)