from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import archivo_txt as t
import base64
#import getpass

class BlowFishCifrado:
    def __init__(self):
        self.tam_bloque = Blowfish.block_size
    
    def cifrar(self, mensaje: str, clave: str) -> str:
        # Convertir la clave y mensaje a bytes
        clave_bytes = clave.encode('utf-8')
        mensaje_bytes = mensaje.encode('utf-8')
        
        # Crear el cifrador
        cifrador = Blowfish.new(clave_bytes, Blowfish.MODE_ECB)
        
        # Aplicar padding y cifrar
        mensaje_cifrado = cifrador.encrypt(pad(mensaje_bytes, self.tam_bloque))
        
        # Codificar en Base64 para mejor manejo
        return base64.b64encode(mensaje_cifrado).decode('utf-8')
    
    def descifrar(self, mensaje_cifrado: str, clave: str) -> str:
        # Convertir la clave a bytes
        clave_bytes = clave.encode('utf-8')
        
        # Decodificar el mensaje cifrado de Base64
        mensaje_cifrado_bytes = base64.b64decode(mensaje_cifrado)
        
        # Crear el cifrador
        cifrador = Blowfish.new(clave_bytes, Blowfish.MODE_ECB)
        
        # Descifrar y remover padding
        mensaje_bytes = unpad(cifrador.decrypt(mensaje_cifrado_bytes), self.tam_bloque)
        
        return mensaje_bytes.decode('utf-8')

    def ejecutar_cifrado(self):
        while True:
            mensaje = str(input('Ingrese una cadena de texto para cifrar: '))
            if mensaje.strip():
                break
            else:
                print('No se ha ingresado ningun mensaje. Porfavor intentelo de nuevo.')
        while True:
            password = str(input('Ingrese clave para cifrar: '))
            if password.strip():
                break
            else:
                print('No se ha ingresado ningun mensaje. Porfavor intentelo de nuevo.')

        resultado = self.cifrar(mensaje, password)
        if resultado.startswith("Error:"):
            print(f"{resultado}")
        else:
            print(f"\n Mensaje cifrado (base 64): {resultado}")
        
        t.crear_txt(resultado)
        
    def ejecutar_descifrado(self):
        mensaje_cifrado = t.leer_txt()
        if not mensaje_cifrado:
            print("No se pudo leer el mensaje cifrado.")
            return
        
        while True:
            clave = input("Ingresa la contraseña para descifrar: ")
            if not clave:
                print("Error: La clave no pueden estar vacíos")
                continue
            
            resultado = self.descifrar(mensaje_cifrado, clave)
            if resultado.startswith("Error"):
                print("La clave es incorrecta. Inténtelo de nuevo.")
                continue
            else:
                print(f"\n✓ Mensaje descifrado: {resultado}")
                break