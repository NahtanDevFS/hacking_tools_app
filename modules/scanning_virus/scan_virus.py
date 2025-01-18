import hashlib
import time
from virus_total_apis import PublicApi
from dotenv import load_dotenv
import os
import tkinter as tk

# Cargar variables de entorno
load_dotenv()

API_KEY = os.getenv('my_virus_total_API') 
api = PublicApi(API_KEY)

def scan_for_virus(file_path_entry, scanning_entry):
    try:
        file_path = file_path_entry.get()

        # Calcular el hash MD5 del archivo
        with open(file_path, "rb") as file:
            file_hash = hashlib.md5(file.read()).hexdigest()

        # Obtener el reporte del archivo a través de su hash
        response = api.get_file_report(file_hash)
    except:
        scanning_entry.delete("1.0", tk.END)  # Limpiar el área de resultados
        return scanning_entry.insert(tk.END, "La ruta del archivo no es válida.")

    scanning_entry.delete("1.0", tk.END)  # Limpiar el área de resultados

    if response["response_code"] == 200:  # La solicitud fue exitosa
        if response["results"]["response_code"] == 1:  # Hay un informe disponible
            positives = response["results"]["positives"]
            total = response["results"]["total"]
            if positives > 0:
                scanning_entry.insert(tk.END, f"Archivo malicioso, tiene {positives} positivos de {total} antivirus.\n")
            else:
                scanning_entry.insert(tk.END, "Archivo seguro.\n")
        else:
            scanning_entry.insert(tk.END, "El archivo no está en la base de datos de virusTotal. Subiendo para su análisis...\n")
            scanning_entry.see(tk.END)  # Desplaza el texto automáticamente hacia abajo
            scanning_entry.update()  # Fuerza la actualización de la interfaz
            upload_and_analyze(file_path, scanning_entry)  # Subir archivo si no existe en la base de datos
    else:
        scanning_entry.insert(tk.END, "Error en la solicitud a VirusTotal.\n")


def upload_and_analyze(file_path, scanning_entry):
    # Subir el archivo para su análisis
    response = api.scan_file(file_path)

    if response["response_code"] == 200 and "results" in response:
        file_hash = response["results"]["md5"]  # Obtener el hash del archivo
        scanning_entry.insert(tk.END, "Archivo subido con éxito. Esperando resultados...\n")
        scanning_entry.see(tk.END) 
        scanning_entry.update() 

        # Esperar y verificar hasta que el análisis esté listo
        for _ in range(60):  # Intenta 6 veces con intervalos de 10 segundos
            time.sleep(10)
            result_response = api.get_file_report(file_hash)
            if result_response["response_code"] == 200:
                if result_response["results"]["response_code"] == 1:  # Informe listo
                    positives = result_response["results"]["positives"]
                    total = result_response["results"]["total"]
                    if positives > 0:
                         scanning_entry.insert(tk.END, f"\nArchivo malicioso, tiene {positives} positivos de {total} antivirus.\n")
                    else:
                        scanning_entry.insert(tk.END, "\nArchivo seguro.\n")
                    return
                else:
                    scanning_entry.insert(tk.END, "Esperando resultados del análisis...\n")
                    scanning_entry.see(tk.END) 
                    scanning_entry.update() 
        scanning_entry.insert(tk.END, "\nEl análisis no se completó a tiempo. Inténtalo más tarde.\n")
    else:
        scanning_entry.insert(tk.END, "Error al subir el archivo.\n")
