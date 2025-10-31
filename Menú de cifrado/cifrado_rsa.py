import archivo_txt as t
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

class CifradoRSA:
    """clase: para cifrar y descifrar mensajes usando el método RSA"""
    
    def __init__(self, clave_publica=None, clave_privada=None):
        """
        inicia la clase RSA con claves opcionales.
        
        atributos:
            clave_publica: clave pública para cifrado (bytes o string base64)
            clave_privada: clave privada para descifrado (bytes o string base64)
        """
        if clave_publica:
            if isinstance(clave_publica, str):
                # Decodificar desde base64
                clave_publica = base64.b64decode(clave_publica.encode('utf-8'))
            self.clave_publica = serialization.load_pem_public_key(clave_publica, backend=default_backend())
        else:
            self.clave_publica = None

        if clave_privada:
            if isinstance(clave_privada, str):
                # Decodificar desde base64
                clave_privada = base64.b64decode(clave_privada.encode('utf-8'))
            self.clave_privada = serialization.load_pem_private_key(
                clave_privada, 
                password=None, 
                backend=default_backend())
        else:
            self.clave_privada = None

    def generar_par_claves(self):
        """
        funcion:
        genera un nuevo par de claves RSA
        
        devuelve:
            tuple: (clave_privada_pem, clave_publica_pem) en base64
        """
        # Generar clave privada RSA
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend())
        clave_publica = clave_privada.public_key()
        
        # Serializar claves
        clave_privada_pem = clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        
        clave_publica_pem = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Codificar en base64
        clave_privada_b64 = base64.b64encode(clave_privada_pem).decode('utf-8')
        clave_publica_b64 = base64.b64encode(clave_publica_pem).decode('utf-8')
        
        return clave_privada_b64, clave_publica_b64

    def cifrar(self, mensaje):
        """
        funcion:
        cifra un mensaje usando RSA con OAEP padding
        
        atributos:
            mensaje: El mensaje a cifrar (str).
        
        devuelve:
            str: Mensaje cifrado en base64.
        """
        # Dividir el mensaje en bloques si es necesario (RSA tiene límite de longitud)
        mensaje_bytes = mensaje.encode('utf-8')
        max_length = self.clave_publica.key_size // 8 - 42  # Restar tamaño de OAEP
        bloques = [mensaje_bytes[i:i + max_length] for i in range(0, len(mensaje_bytes), max_length)]
        
        cifrado_bloques = []
        for bloque in bloques:
            cifrado = self.clave_publica.encrypt(
                bloque,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            cifrado_bloques.append(cifrado)
        
        # Combinar bloques y codificar en base64
        mensaje_cifrado = b''.join(cifrado_bloques)
        return base64.b64encode(mensaje_cifrado).decode('utf-8')

    def descifrar(self, mensaje_cifrado_b64):
        """
        funcion:
        descifra un mensaje cifrado usando RSA
        
        atributos:
            mensaje_cifrado_b64: El mensaje cifrado en base64 (str).
        
        devuelve:
            str: Mensaje descifrado.
        """
        mensaje_cifrado = base64.b64decode(mensaje_cifrado_b64.encode('utf-8'))
        
        # Dividir en bloques (asumiendo que cada bloque es del tamaño de la clave)
        bloque_size = self.clave_privada.key_size // 8
        bloques = [mensaje_cifrado[i:i + bloque_size] for i in range(0, len(mensaje_cifrado), bloque_size)]
        
        descifrado_bloques = []
        for bloque in bloques:
            descifrado = self.clave_privada.decrypt(
                bloque,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            descifrado_bloques.append(descifrado)
        
        return b''.join(descifrado_bloques).decode('utf-8')

    def ejecutar_cifrado_txt(self):
        """
        funcion:
        permite ingresar el mensaje a cifrar y guardarlo en un archivo .txt junto con la clave
        """
        mensaje = input("Ingrese el mensaje a cifrar: ")
        if not self.clave_publica:
            clave_publica_b64 = input("Ingrese la clave pública RSA (en base64): ")
            try:
                clave_publica_bytes = base64.b64decode(clave_publica_b64.encode('utf-8'))
                self.clave_publica = serialization.load_pem_public_key(clave_publica_bytes, backend=default_backend())
            except Exception as e:
                print(f"Error al cargar la clave pública: {e}")
                return
        if not self.clave_privada:
            # Generar par de claves si no existen
            print("Generando nuevo par de claves RSA")
            clave_privada_b64, clave_publica_b64 = self.generar_par_claves()
            self.clave_publica = serialization.load_pem_public_key(
                base64.b64decode(clave_publica_b64.encode('utf-8')), 
                backend=default_backend())
            
            print(f"Clave pública generada: {clave_publica_b64[:50]}...")
            print("Guarde su clave privada para poder descifrar:")    
            
            clavepriv_txt=input("Ingrese el nombre del archivo para crearlo (sin la extensión): ")
            clavepriv_txt += ".txt" #agrega la extension .txt a la clave 
            
            with open(clavepriv_txt, mode='w', newline='', encoding='utf-8') as priv:
                priv.write(clave_privada_b64)
            print(f"El archivo '{clavepriv_txt}' ha sido creado con el mensaje cifrado.")            
            print(f"Clave privada: {clave_privada_b64}")
        
        try:
            print("Cifrando mensaje...")
            mensaje_cifrado = self.cifrar(mensaje)
            t.crear_txt(mensaje_cifrado)
            print("Mensaje cifrado y guardado exitosamente.")
        except Exception as e:
            print(f"Error al cifrar: {e}")

    def ejecutar_descifrado_txt(self):
        """
        funcion:
        descifra un mensaje leído de un archivo .txt y lo imprime en la terminal
        """
        mensaje_cifrado = t.leer_txt()
        if mensaje_cifrado is None:
            print("No se pudo leer el mensaje cifrado del archivo txt.")
            return
        
        if not self.clave_privada:
            while True:
                clave_privada_b64 = input("Ingrese su clave privada RSA (en base64): ")
                try:
                    clave_privada_bytes = base64.b64decode(clave_privada_b64.encode('utf-8'))
                    self.clave_privada = serialization.load_pem_private_key(
                        clave_privada_bytes, 
                        password=None, 
                        backend=default_backend())
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
                    clave_privada_b64 = input("Ingrese su clave privada RSA (en base64): ")
                    try:
                        clave_privada_bytes = base64.b64decode(clave_privada_b64.encode('utf-8'))
                        self.clave_privada = serialization.load_pem_private_key(
                            clave_privada_bytes, 
                            password=None, 
                            backend=default_backend())
                        break
                    except Exception as e:
                        print("Error al cargar la clave privada. Inténtelo de nuevo.")
                        continue