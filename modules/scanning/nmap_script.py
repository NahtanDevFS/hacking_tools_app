import nmap
import tkinter as tk
from tkinter import scrolledtext

def perform_scan(ip_entry, ports_entry, results_text):
    target = ip_entry.get()  # Obtener la IP o el rango de red del campo de entrada
    ports = ports_entry.get()  # Obtener los puertos a escanear
    results_text.delete("1.0", tk.END)  # Limpiar el área de resultados

    if not target:
        results_text.insert(tk.END, "Por favor, introduce una dirección IP o un rango de red.\n")
        return

    if not ports:
        ports = "1-1024"  # Escanear puertos comunes si no se especifica

    results_text.insert(tk.END, f"Escaneando {target} en los puertos {ports}...\n")
    results_text.see(tk.END)  # Desplaza el texto automáticamente hacia abajo
    results_text.update()  # Fuerza la actualización de la interfaz
    try:
        nm = nmap.PortScanner()
        nm.scan(target, ports)
        for host in nm.all_hosts():
            results_text.insert(tk.END, f"\nHost: {host} ({nm[host].hostname()})\n")
            results_text.insert(tk.END, f"Estado: {nm[host].state()}\n")
            for protocol in nm[host].all_protocols():
                results_text.insert(tk.END, f"Protocolo: {protocol}\n")
                ports = nm[host][protocol].keys()
                for port in ports:
                    state = nm[host][protocol][port]['state']
                    results_text.insert(tk.END, f"  Puerto: {port}\tEstado: {state}\n")
    except nmap.PortScannerError as nse:
        results_text.insert(tk.END, f"Error al realizar el escaneo con nmap: {nse}\n")
    except Exception as e:
        results_text.insert(tk.END, f"Error inesperado: {e}\n")
