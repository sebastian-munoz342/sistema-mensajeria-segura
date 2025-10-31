"""se importa el módulo creador para manejar operaciones con archivos .txt"""
import archivo_txt as t
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
from Crypto.Util.Padding import pad, unpad  # Añadida la importación de pad y unpad

class CifradoECC:
    """clase: para cifrar y descifrar mensajes usando el método ECC (Elliptic Curve Cryptography)"""
    
    def __init__(self, clave_publica=None, clave_privada=None):
        """
        inicia la clase ECC con claves opcionales.
        
        atributos:
            clave_publica: clave pública para cifrado (bytes o string base64)
            clave_privada: clave privada para descifrado (bytes o string base64)
        """
        if clave_publica:
            if isinstance(clave_publica, str):
                clave_publica = base64.b64decode(clave_publica.encode('utf-8'))
            self.clave_publica = serialization.load_pem_public_key(clave_publica, backend=default_backend())
        else:
            self.clave_publica = None
            
        if clave_privada:
            if isinstance(clave_privada, str):
                clave_privada = base64.b64decode(clave_privada.encode('utf-8'))
            self.clave_privada = serialization.load_pem_private_key(
                clave_privada, 
                password=None, 
                backend=default_backend()
            )
        else:
            self.clave_privada = None

    def generar_par_claves(self):
        """
        funcion:
        genera un nuevo par de claves ECC
        
        devuelve:
            tuple: (clave_privada_pem, clave_publica_pem) en base64
        """
        clave_privada = ec.generate_private_key(ec.SECP256R1(), default_backend())
        clave_publica = clave_privada.public_key()
        
        clave_privada_pem = clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        clave_publica_pem = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        clave_privada_b64 = base64.b64encode(clave_privada_pem).decode('utf-8')
        clave_publica_b64 = base64.b64encode(clave_publica_pem).decode('utf-8')
        
        return clave_privada_b64, clave_publica_b64

    def cifrar(self, mensaje):
        """
        funcion:
        cifra un mensaje usando ECC + AES (para cifrado hibrido)
        
        atributos:
            mensaje: El mensaje a cifrar (str).
        
        devuelve:
            str: Mensaje cifrado en base64.
        """
        clave_efimera_privada = ec.generate_private_key(ec.SECP256R1(), default_backend())
        clave_efimera_publica = clave_efimera_privada.public_key()
        
        clave_compartida = clave_efimera_privada.exchange(ec.ECDH(), self.clave_publica)
        
        clave_aes = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(clave_compartida)
        
        iv = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        mensaje_bytes = mensaje.encode('utf-8')
        padded_data = pad(mensaje_bytes, 16)  # Usando la función pad importada
        ct = encryptor.update(padded_data) + encryptor.finalize()
        
        clave_efimera_pem = clave_efimera_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        mensaje_cifrado = clave_efimera_pem + iv + ct
        
        return base64.b64encode(mensaje_cifrado).decode('utf-8')

    def descifrar(self, mensaje_cifrado_b64):
        """
        funcion:
        descifra un mensaje cifrado usando ECC + AES
        
        atributos:
            mensaje_cifrado_b64: El mensaje cifrado en base64 (str).
        
        devuelve:
            str: Mensaje descifrado.
        """
        mensaje_cifrado = base64.b64decode(mensaje_cifrado_b64.encode('utf-8'))
        
        fin_pem = mensaje_cifrado.find(b'-----END PUBLIC KEY-----') + 24
        clave_efimera_pem = mensaje_cifrado[:fin_pem]
        
        clave_efimera_publica = serialization.load_pem_public_key(clave_efimera_pem, backend=default_backend())
        
        clave_compartida = self.clave_privada.exchange(ec.ECDH(), clave_efimera_publica)
        
        clave_aes = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(clave_compartida)
        
        iv = mensaje_cifrado[fin_pem:fin_pem+16]
        ct = mensaje_cifrado[fin_pem+16:]
        
        cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        
        unpadded_data = unpad(padded_data, 16)  # Usando la función unpad importada
        
        return unpadded_data.decode('utf-8')

    def ejecutar_cifrado_txt(self):
        """
        funcion:
        permite ingresar el mensaje a cifrar y guardarlo en un archivo .txt
        """
        mensaje = input("Ingrese el mensaje a cifrar: ")
        if not self.clave_publica:
            clave_publica_b64 = input("Ingrese la clave pública ECC (en base64): ")
            try:
                clave_publica_bytes = base64.b64decode(clave_publica_b64.encode('utf-8'))
                self.clave_publica = serialization.load_pem_public_key(clave_publica_bytes, backend=default_backend())
            except Exception as e:
                print(f"Error al cargar la clave pública: {e}")
                return
        if not self.clave_privada:
            print("Generando nuevo par de claves ECC")
            clave_privada_b64, clave_publica_b64 = self.generar_par_claves()
            self.clave_publica = serialization.load_pem_public_key(
                base64.b64decode(clave_publica_b64.encode('utf-8')), 
                backend=default_backend())
            print(f"Clave pública generada: {clave_publica_b64[:50]}...")
            print("Guarde su clave privada para poder descifrar:")
            
            clavepriv_txt=input("Ingrese el nombre del archivo para crearlo (sin la extensión): ")
            clavepriv_txt += ".txt"
            
            with open(clavepriv_txt, mode='w', newline='', encoding='utf-8') as priv:
                priv.write(clave_privada_b64)
            print(f"El archivo '{clavepriv_txt}' ha sido creado con el mensaje cifrado.")            
            print(f"Clave privada: {clave_privada_b64}")
        
        mensaje_cifrado = self.cifrar(mensaje)
        t.crear_txt(mensaje_cifrado)

    def ejecutar_descifrado_txt(self):
        mensaje_cifrado = t.leer_txt()
        if mensaje_cifrado is None:
            print("No se pudo leer el mensaje cifrado del archivo TXT.")
            return
        
        if not self.clave_privada:
            while True:
                clave_privada_b64 = input("Ingrese su clave privada ECC (en base64): ")
                try:
                    clave_privada_bytes = base64.b64decode(clave_privada_b64.encode('utf-8'))
                    self.clave_privada = serialization.load_pem_private_key(
                        clave_privada_bytes, 
                        password=None, 
                        backend=default_backend()
                    )
                    break
                except Exception as e:
                    print("Error al cargar la clave privada. Inténtelo de nuevo.")
                    continue
        while True:
            try:
                mensaje_descifrado = self.descifrar(mensaje_cifrado)
                print("Mensaje descifrado:", mensaje_descifrado)
                break
            except Exception as e:
                print("La clave es incorrecta o hay un error en el descifrado. Inténtelo de nuevo.")
                while True:
                    clave_privada_b64 = input("Ingrese su clave privada ECC (en base64): ")
                    try:
                        clave_privada_bytes = base64.b64decode(clave_privada_b64.encode('utf-8'))
                        self.clave_privada = serialization.load_pem_private_key(
                            clave_privada_bytes, 
                            password=None, 
                            backend=default_backend()
                        )
                        break
                    except Exception as e:
                        print("Error al cargar la clave privada. Inténtelo de nuevo.")
                        continue