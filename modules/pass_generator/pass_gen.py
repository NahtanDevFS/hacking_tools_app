import tkinter as tk
from tkinter import scrolledtext
import random
import string

def generate_password(entry_contrasena):
    longitud = 12  # Longitud de la contraseña
    caracteres = string.ascii_letters + string.digits + string.punctuation
    contrasena = ''.join(random.choice(caracteres) for _ in range(longitud))
    entry_contrasena.delete(0, tk.END)
    entry_contrasena.insert(tk.END, contrasena)