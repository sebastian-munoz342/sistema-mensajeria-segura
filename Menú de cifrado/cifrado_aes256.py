import base64
import os
import archivo_txt as T
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

class AESCifrado:
    def __init__(self):
        """Inicializa el cifrado AES."""
        self.salt = b'salt_fijo_16bytes'  
        self.clave = None  

    def _get_key(self, password: str):
        """Deriva una clave AES-256 desde la contraseña usando PBKDF2."""
        return PBKDF2(password.encode('utf-8'), self.salt, 32, count=100000)

    def cifrar(self, mensaje: str, password: str) -> str:
        """Cifra un mensaje usando AES-256 en modo CBC."""
        key = self._get_key(password)
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        mensaje_bytes = mensaje.encode('utf-8')
        mensaje_cifrado = cipher.encrypt(pad(mensaje_bytes, AES.block_size))
        return base64.b64encode(iv + mensaje_cifrado).decode('utf-8')

    def descifrar(self, mensaje_cifrado: str, password: str) -> str:
        """Descifra un mensaje cifrado con AES-256 en modo CBC."""
        try:
            key = self._get_key(password)
            datos = base64.b64decode(mensaje_cifrado)
            iv = datos[:16]
            texto_cifrado = datos[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            mensaje_descifrado = unpad(cipher.decrypt(texto_cifrado), AES.block_size)
            return mensaje_descifrado.decode('utf-8')
        except Exception as e:
            return f"Error al descifrar: {e}"

    def ejecutar_cifrado(self):
        print("\n--- CIFRAR MENSAJE ---")
        mensaje = input("Ingrese el mensaje a cifrar: ")
        password = input("Ingrese la contraseña: ")

        if not mensaje or not password:
            print("Error: El mensaje y la clave no pueden estar vacíos.")
            return
        
        resultado = self.cifrar(mensaje, password)
        print(f"\nMensaje cifrado (base64): {resultado}")
        T.crear_txt(resultado)
        print("El mensaje cifrado fue guardado en un archivo .txt")

    def ejecutar_descifrado(self):
        """Ejecuta el proceso de descifrado"""
        print("\n--- DESCIFRAR MENSAJE ---")
        mensaje_cifrado = T.leer_txt()

        if not mensaje_cifrado:
            print("No se pudo leer el mensaje cifrado del archivo TXT.")
            return
        
        while True:
            self.clave = input("Ingrese la clave usada para cifrar: ")
            resultado = self.descifrar(mensaje_cifrado, self.clave)
            if resultado.startswith("Error"):
                print("La clave es incorrecta. Inténtelo de nuevo.")
                continue
            else:
                print(f"\nMensaje descifrado: {resultado}")
                break