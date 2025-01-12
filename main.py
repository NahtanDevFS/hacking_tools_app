
import nmap
import socket
import struct
import fcntl
import os
import sys

try:
    module_path = os.path.abspath(os.path.join("modules/scanning"))
    if module_path not in sys.path:
        sys.path.append(module_path)

    module_path = os.path.abspath(os.path.join("modules/pass_generator"))
    if module_path not in sys.path:
        sys.path.append(module_path)

    import tkinter as tk
    from tkinter import ttk, scrolledtext
    from nmap_script import perform_scan
    from pass_gen import generate_password
except ModuleNotFoundError as e:
    print(e)
    exit(1)


def get_local_ipv4():
    try:
        # Connect to an external server to determine the interface in use
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # 8.8.8.8 is Google's public DNS server
            local_ip = s.getsockname()[0]
        return local_ip
    except Exception as e:
        print(f"Error: {e}")
        return None

# Función para listar dispositivos conectados a la red Wi-Fi
def list_connected_devices():
    devices_text.delete("1.0", tk.END)  # Limpiar el área de resultados
    try:
        nm = nmap.PortScanner()
        local_ipv4 = get_local_ipv4()
        subnet = f"{local_ipv4}/24"
        devices_text.insert(tk.END, f"Escaneando dispositivos en la red {subnet}...\n")
        nm.scan(hosts=subnet, arguments="-sn")
        for host in nm.all_hosts():
            devices_text.insert(tk.END, f"Host: {host} ({nm[host].hostname()}) - Estado: {nm[host].state()}\n")
    except Exception as e:
        devices_text.insert(tk.END, f"Error al escanear la red: {e}\n")

# GUI principal
root = tk.Tk()
root.title("Aplicación para Hacking userFriendly")
root.geometry("900x600")
root.configure(bg="black")  # Cambiar el fondo a gris oscuro

# Crear estilos personalizados
style = ttk.Style()
style.configure("TFrame", background="black")
style.configure("TLabel", background="black", foreground="#03bf00")
style.configure("TButton", background="black", foreground="#03bf00")

# Contenedor de pestañas
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Pestañas
home_tab = ttk.Frame(notebook, style="TFrame")
devices_tab = ttk.Frame(notebook, style="TFrame")
scan_tab = ttk.Frame(notebook, style="TFrame")
exploit_tab = ttk.Frame(notebook, style="TFrame")
post_exploit_tab = ttk.Frame(notebook, style="TFrame")
#extra tabs
pass_generator_tab = ttk.Frame(notebook, style="TFrame")
pass_cracker_tab = ttk.Frame(notebook, style="TFrame")
intercept_data_network_tab = ttk.Frame(notebook, style="TFrame")

notebook.add(home_tab, text="Inicio")
notebook.add(devices_tab, text="Escaneo Red")
notebook.add(scan_tab, text="Escaneo Puertos")
notebook.add(exploit_tab, text="Exploit")
notebook.add(post_exploit_tab, text="Post-exploit")
notebook.add(pass_generator_tab, text="Gen-clave")
notebook.add(pass_cracker_tab, text="Crack-clave")
notebook.add(intercept_data_network_tab, text="interceptar datos de red")

# Contenido de la pestaña Inicio
home_label = ttk.Label(home_tab, text="Bienvenido a tu aplicación de Hacking", font=("Arial", 16))
home_label.pack(pady=20)

scan_button = tk.Button(home_tab, text="Escanear puertos", command=lambda: notebook.select(scan_tab), width=30, bg="#303030", fg="#03bf00")
scan_button.pack(pady=10)

devices_button = tk.Button(home_tab, text="Escanear Red", command=lambda: notebook.select(devices_tab), width=30, bg="#303030", fg="#03bf00")
devices_button.pack(pady=10)

devices_button = tk.Button(home_tab, text="Iniciar exploit", command=lambda: notebook.select(exploit_tab), width=30, bg="#303030", fg="#03bf00")
devices_button.pack(pady=10)

devices_button = tk.Button(home_tab, text="Reporte post-exploit", command=lambda: notebook.select(post_exploit_tab), width=30, bg="#303030", fg="#03bf00")
devices_button.pack(pady=10)

extras_label = ttk.Label(home_tab, text="Extras", font=("Arial", 16))
extras_label.pack(pady=20)

devices_button = tk.Button(home_tab, text="Generador de contraseñas", command=lambda: notebook.select(pass_generator_tab), width=30, bg="#303030", fg="#03bf00")
devices_button.pack(pady=10)

devices_button = tk.Button(home_tab, text="Crack de fuerza bruta de contraseñas", command=lambda: notebook.select(pass_cracker_tab), width=30, bg="#303030", fg="#03bf00")
devices_button.pack(pady=10)

devices_button = tk.Button(home_tab, text="Interceptar datos compartidos en la Red", command=lambda: notebook.select(intercept_data_network_tab), width=30, bg="#303030", fg="#03bf00")
devices_button.pack(pady=10)



# Contenido de la pestaña Escaneo
scan_label = ttk.Label(scan_tab, text="Herramientas de Escaneo con Nmap", font=("Arial", 14))
scan_label.pack(pady=10)

# Campo de entrada para la IP o rango de red
ip_label = ttk.Label(scan_tab, text="Dirección IP o Rango de Red:")
ip_label.pack(pady=5)
ip_entry = tk.Entry(scan_tab, width=50, bg="#303030", fg="#03bf00")
ip_entry.pack(pady=5)

# Campo de entrada para los puertos
ports_label = ttk.Label(scan_tab, text="Puertos (ejemplo: 22,80 o 1-1024):")
ports_label.pack(pady=5)
ports_entry = tk.Entry(scan_tab, width=50, bg="#303030", fg="#03bf00")
ports_entry.pack(pady=5)

# Botón para ejecutar el escaneo
scan_action_button = tk.Button(scan_tab, text="Ejecutar Escaneo", command=lambda: perform_scan(ip_entry, ports_entry, results_text), width=30, bg="#303030", fg="#03bf00")
scan_action_button.pack(pady=10)

# Área para mostrar los resultados
results_label = ttk.Label(scan_tab, text="Resultados:")
results_label.pack(pady=5)
results_text = scrolledtext.ScrolledText(scan_tab, width=80, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
results_text.pack(pady=5)




# Contenido de la pestaña Dispositivos Conectados
devices_label = ttk.Label(devices_tab, text="Dispositivos Conectados a la Red Wi-Fi", font=("Arial", 14))
devices_label.pack(pady=10)

# Botón para listar dispositivos
list_devices_button = tk.Button(devices_tab, text="Listar Dispositivos", command=list_connected_devices, width=30, bg="#303030", fg="#03bf00")
list_devices_button.pack(pady=10)

# Área para mostrar los resultados
devices_text = scrolledtext.ScrolledText(devices_tab, width=80, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
devices_text.pack(pady=5)



#Contenido de la pestaña del generador de contraseñas seguras
pass_gen_label = ttk.Label(pass_generator_tab, text="Pulse el botón para crear una contraseña totalmente segura", font=("Arial", 16))
pass_gen_label.pack(pady=30)
list_devices_button = tk.Button(pass_generator_tab, text="Generar contraseña", command=lambda: generate_password(pass_entry), width=30, bg="#303030", fg="#03bf00")
list_devices_button.pack(pady=50)
pass_entry = tk.Entry(pass_generator_tab, width=20, bg="#303030", fg="#03bf00", font=("Arial", 16))
pass_entry.pack(pady=30)

# Iniciar la GUI
root.mainloop()