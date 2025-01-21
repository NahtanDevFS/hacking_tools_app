
import nmap
import socket
import struct
import fcntl
import os
import sys

try:

    modules = [
        "modules/scanning",
        "modules/pass_generator",
        "modules/reconnaissance",
        "modules/scanning_virus",
        "modules/access_point",
        "modules/redirection",
        "modules/interception",
    ]
    for module in modules:
        module_path = os.path.abspath(os.path.join(module))
        if module_path not in sys.path:
            sys.path.append(module_path)

    import tkinter as tk
    from tkinter import ttk, scrolledtext
    from nmap_script import perform_scan
    from pass_gen import generate_password
    from get_IP_net_devices import list_connected_devices
    from scan_virus import scan_for_virus
    from run_response import ejecutar_ettercap_en_hilo, ejecutar_mitmdump, parar_ettercap_en_hilo, parar_mitmdump
    from start_server_fake_form import start_http_server_en_hilo, stop_http_server, actualizar_consola_http_server
except ModuleNotFoundError as e:
    print(e)
    exit(1)


# GUI principal
root = tk.Tk()
root.title("Aplicación para Hacking userFriendly")
root.geometry("1200x600")
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
ettercap_tab = ttk.Frame(notebook, style="TFrame")
mitmdump_tab = ttk.Frame(notebook, style="TFrame")
intercept_data_network_tab = ttk.Frame(notebook, style="TFrame")
# Pestañas extra
pass_generator_tab = ttk.Frame(notebook, style="TFrame")
scan_virus_tab = ttk.Frame(notebook, style="TFrame")

notebook.add(home_tab, text="Inicio")
notebook.add(devices_tab, text="Escaneo Red")
notebook.add(scan_tab, text="Escaneo Puertos")
notebook.add(ettercap_tab, text="Iniciar-ettercap")
notebook.add(mitmdump_tab, text="Iniciar-mitmdump")
notebook.add(intercept_data_network_tab, text="interceptar trafico de red")
notebook.add(pass_generator_tab, text="Gen-clave")
notebook.add(scan_virus_tab, text="Scan-archivo")

# Contenido de la pestaña Inicio
home_label = ttk.Label(home_tab, text="Bienvenido a tu aplicación de Hacking", font=("Arial", 16))
home_label.pack(pady=20)

devices_button = tk.Button(home_tab, text="Escanear Red", command=lambda: notebook.select(devices_tab), width=40, bg="#303030", fg="#03bf00")
devices_button.pack(pady=10)

scan_button = tk.Button(home_tab, text="Escanear puertos", command=lambda: notebook.select(scan_tab), width=40, bg="#303030", fg="#03bf00")
scan_button.pack(pady=10)

ettercap_button = tk.Button(home_tab, text="Ir a iniciar ettercap", command=lambda: notebook.select(ettercap_tab), width=40, bg="#303030", fg="#03bf00")
ettercap_button.pack(pady=10)

mitmdump_button = tk.Button(home_tab, text="Ir a iniciar mitmdump", command=lambda: notebook.select(mitmdump_tab), width=40, bg="#303030", fg="#03bf00")
mitmdump_button.pack(pady=10)

intercept_data_button = tk.Button(home_tab, text="Interceptar tráfico en la Red", command=lambda: notebook.select(intercept_data_network_tab), width=40, bg="#303030", fg="#03bf00")
intercept_data_button.pack(pady=10)

extras_label = ttk.Label(home_tab, text="Extras", font=("Arial", 16))
extras_label.pack(pady=20)

generator_password_button = tk.Button(home_tab, text="Generador de contraseñas", command=lambda: notebook.select(pass_generator_tab), width=40, bg="#303030", fg="#03bf00")
generator_password_button.pack(pady=10)

malware_scanner_button = tk.Button(home_tab, text="Escáneo de archivos para detectar malware", command=lambda: notebook.select(scan_virus_tab), width=40, bg="#303030", fg="#03bf00")
malware_scanner_button.pack(pady=10)




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
list_devices_button = tk.Button(devices_tab, text="Listar Dispositivos", command=lambda: list_connected_devices(devices_text), width=30, bg="#303030", fg="#03bf00")
list_devices_button.pack(pady=10)

# Área para mostrar los resultados
devices_text = scrolledtext.ScrolledText(devices_tab, width=80, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
devices_text.pack(pady=5)



#Contenido de la pestaña para iniciar ettercap
ettercap_label = ttk.Label(ettercap_tab, text="Manejo de ettercap", font=("Arial", 16))
ettercap_label.pack(pady=10)
ettercap_ip_victim_label = ttk.Label(ettercap_tab, text="Introduce la IP de la víctima", font=("Arial", 16))
ettercap_ip_victim_label.pack(pady=10)

victim_ip_entry = tk.Entry(ettercap_tab, width=50, bg="#303030", fg="#03bf00")
victim_ip_entry.pack(pady=5)
start_ettercap_button = tk.Button(ettercap_tab, text="Iniciar ettercap", command=lambda: ejecutar_ettercap_en_hilo(ettercap_result_text, victim_ip_entry), width=30, bg="#303030", fg="#03bf00")
start_ettercap_button.pack(pady=10)
stop_ettercap_button = tk.Button(ettercap_tab, text="Parar ettercap", command=lambda: parar_ettercap_en_hilo(ettercap_result_text), width=30, bg="#303030", fg="#03bf00")
stop_ettercap_button.pack(pady=10)
ettercap_result_text = scrolledtext.ScrolledText(ettercap_tab, width=100, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
ettercap_result_text.pack(pady=5)




#Contenido de la pestaña para iniciar mitmdump
mitmdump_label = ttk.Label(mitmdump_tab, text="Manejo de mitmdump", font=("Arial", 16))
mitmdump_label.pack(pady=10)
start_mitmdump_button = tk.Button(mitmdump_tab, text="Iniciar mitmdump", command=lambda: ejecutar_mitmdump(mitmdump_result_text), width=30, bg="#303030", fg="#03bf00")
start_mitmdump_button.pack(pady=10)
start_mitmdump_button = tk.Button(mitmdump_tab, text="Parar mitmdump", command=lambda: parar_mitmdump(mitmdump_result_text), width=30, bg="#303030", fg="#03bf00")
start_mitmdump_button.pack(pady=10)
mitmdump_result_text = scrolledtext.ScrolledText(mitmdump_tab, width=100, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
mitmdump_result_text.pack(pady=5)



#Contenido de la pestaña para iniciar la interceptacion
interception_label = ttk.Label(intercept_data_network_tab, text="Manejo de intercepcion de trafico", font=("Arial", 16))
interception_label.pack(pady=10)
start_http_server_button = tk.Button(intercept_data_network_tab, text="Iniciar http server", command=lambda: start_http_server_en_hilo(http_server_result_text), width=30, bg="#303030", fg="#03bf00")
start_http_server_button.pack(pady=10)
stop_http_server_button = tk.Button(intercept_data_network_tab, text="detener http server", command=lambda: stop_http_server(http_server_result_text), width=30, bg="#303030", fg="#03bf00")
stop_http_server_button.pack(pady=10)
http_server_result_text = scrolledtext.ScrolledText(intercept_data_network_tab, width=120, height=12, bg="#303030", fg="#03bf00", insertbackground="white")
http_server_result_text.pack(pady=5)

start_interception_button = tk.Button(intercept_data_network_tab, text="Actualizar consola", command=lambda: actualizar_consola_http_server(http_server_result_text), width=30, bg="#303030", fg="#03bf00")
start_interception_button.pack(pady=10)


#Contenido de la pestaña del generador de contraseñas seguras
pass_gen_label = ttk.Label(pass_generator_tab, text="Introduzca la longitud de la contraseña (longitud 12 recomendada)", font=("Arial", 16))
pass_gen_label.pack(pady=10)
pass_length_entry = tk.Entry(pass_generator_tab, width=20, bg="#303030", fg="#03bf00", font=("Arial", 16))
pass_length_entry.pack(pady=10)
pass_gen_label = ttk.Label(pass_generator_tab, text="Pulse el botón para crear una contraseña totalmente segura", font=("Arial", 16))
pass_gen_label.pack(pady=10)
list_devices_button = tk.Button(pass_generator_tab, text="Generar contraseña", command=lambda: generate_password(pass_entry, pass_length_entry), width=30, bg="#303030", fg="#03bf00")
list_devices_button.pack(pady=10)
pass_entry = tk.Entry(pass_generator_tab, width=50, bg="#303030", fg="#03bf00", font=("Arial", 14))
pass_entry.pack(pady=20)



#Contenido de la pestaña para escanear archivos maliciosos
pass_gen_label = ttk.Label(scan_virus_tab, text="Introduzca la ruta del archivo que quiere analizar", font=("Arial", 16))
pass_gen_label.pack(pady=10)
file_path_entry = tk.Entry(scan_virus_tab, width=50, bg="#303030", fg="#03bf00", font=("Arial", 14))
file_path_entry.pack(pady=20)
exec_scan_button = tk.Button(scan_virus_tab, text="Realizar escaneo", command=lambda: scan_for_virus(file_path_entry, analisis_result_text), width=30, bg="#303030", fg="#03bf00")
exec_scan_button.pack(pady=10)
analisis_result_text = scrolledtext.ScrolledText(scan_virus_tab, width=80, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
analisis_result_text.pack(pady=5)


# Iniciar la GUI
root.mainloop()