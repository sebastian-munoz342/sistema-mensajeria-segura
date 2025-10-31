from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
import re
import archivo_txt as t

class DESCifrado:
    def __init__(self):
        pass
    
    def _limpiar_cadena_base64(self, cadena):
        """Limpia la cadena base64 eliminando espacios y caracteres especiales"""
        cadena_limpia = re.sub(r'[^A-Za-z0-9+/=]', '', cadena)
        return cadena_limpia
    
    def _preparar_clave(self, clave):
        """Prepara la clave para que tenga exactamente 8 bytes"""
        clave_bytes = clave.encode('utf-8')
        if len(clave_bytes) < 8:
            clave_bytes = clave_bytes.ljust(8, b'\0')
        elif len(clave_bytes) > 8:
            clave_bytes = clave_bytes[:8]
        return clave_bytes
    
    def cifrar(self, mensaje, clave):
        """Cifra un mensaje usando DES"""
        try:
            # Asegurar que la clave tenga exactamente 8 bytes
            clave_bytes = self._preparar_clave(clave)
            
            # Crear cifrador en modo ECB
            cipher = DES.new(clave_bytes, DES.MODE_ECB)
            
            # Aplicar padding y cifrar
            mensaje_bytes = mensaje.encode('utf-8')
            mensaje_cifrado = cipher.encrypt(pad(mensaje_bytes, DES.block_size))
            
            # Convertir a base64 para mejor manejo
            return base64.b64encode(mensaje_cifrado).decode('utf-8')
        
        except Exception as e:
            return f"Error al cifrar: {str(e)}"
    
    def descifrar(self, mensaje_cifrado_b64, clave):
        """Descifra un mensaje usando DES"""
        try:
            # Limpiar la cadena base64
            mensaje_cifrado_b64 = self._limpiar_cadena_base64(mensaje_cifrado_b64)
            
            # Verificar que la longitud sea múltiplo de 4 (requerido para base64)
            if len(mensaje_cifrado_b64) % 4 != 0:
                # Añadir padding '=' si es necesario
                mensaje_cifrado_b64 += '=' * (4 - len(mensaje_cifrado_b64) % 4)
            
            # Asegurar que la clave tenga exactamente 8 bytes
            clave_bytes = self._preparar_clave(clave)
            
            # Crear cifrador en modo ECB
            cipher = DES.new(clave_bytes, DES.MODE_ECB)
            
            # Convertir de base64 y descifrar
            mensaje_cifrado = base64.b64decode(mensaje_cifrado_b64)
            mensaje_bytes = unpad(cipher.decrypt(mensaje_cifrado), DES.block_size)
            
            return mensaje_bytes.decode('utf-8')
        
        except Exception as e:
            return f"Error al descifrar: {str(e)}"

    def ejecutar_cifrado(self):
        while True:
            mensaje = str(input('Ingrese una cadena de texto para cifrar: '))
            if mensaje.strip():
                break
            else:
                print('No se ha ingresado ningun mensaje. Porfavor intentelo de nuevo.')
        while True:
            password = str(input('Ingrese una clave para cifrar: '))
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
                print(f"\nMensaje descifrado: {resultado}")
                break