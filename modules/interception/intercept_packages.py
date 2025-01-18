from scapy.all import sniff
import tkinter as tk

def start_intercept_packages(packages_entry):
    def packet_callback(packet):
        if packet.haslayer('Raw'):  # Verifica si hay datos en texto plano
            payload = packet['Raw'].load
            if b'POST' in payload or b'GET' in payload:  # Busca solicitudes HTTP
                packages_entry.delete("1.0", tk.END)
                packages_entry.insert(tk.END, f"[HTTP Request] {payload}\n")
                print(f"[HTTP Request] {payload}")

    # Escucha en la interfaz de red (por ejemplo, 'eth0')
    sniff(filter="tcp port 9000", prn=packet_callback, store=False)