"""se importa el módulo creador para manejar operaciones con archivos .txt y .bin"""
import archivo_txt as t
import random
import base64
import sympy

class CifradoElGamal:
    """clase: para cifrar y descifrar mensajes usando el método ElGamal"""
    
    def __init__(self, clave_publica=None, clave_privada=None):
        """
        inicia la clase ElGamal con claves opcionales.
        
        atributos:
            clave_publica: clave pública para cifrado (string base64)
            clave_privada: clave privada para descifrado (string base64)
        """
        self.clave_publica_b64 = clave_publica
        self.clave_privada_b64 = clave_privada
        
        if clave_publica:
            self.clave_publica = self._deserializar_clave(clave_publica)
        else:
            self.clave_publica = None
            
        if clave_privada:
            self.clave_privada = self._deserializar_clave(clave_privada)
        else:
            self.clave_privada = None

    def _encontrar_generador(self, p):
        """Encuentra un generador del grupo multiplicativo módulo p"""
        for g in range(2, p):
            if all(pow(g, (p-1)//q, p) != 1 for q in sympy.primefactors(p-1)):
                return g
        raise ValueError("No se pudo encontrar un generador para p")

    def _serializar_clave(self, clave):
        """Serializa una clave a base64"""
        return base64.b64encode(str(clave).encode('utf-8')).decode('utf-8')

    def _deserializar_clave(self, clave_b64):
        """Deserializa una clave desde base64"""
        clave_str = base64.b64decode(clave_b64.encode('utf-8')).decode('utf-8')
        return eval(clave_str)  # Nota: Esto es inseguro en producción; usa un formato seguro en un caso real

    def generar_par_claves(self):
        """
        funcion:
        genera un nuevo par de claves ElGamal
        
        devuelve:
            tuple: (clave_privada_b64, clave_publica_b64) en base64
        """
        print("Generando primo")
        # Usar un primo más pequeño para desarrollo (128 bits)
        p = sympy.randprime(2**127, 2**128)
        print(f"Primo p generado: {p}")
        
        print("Buscando generador g")
        # Encontrar un generador g del grupo multiplicativo módulo p
        g = self._encontrar_generador(p)
        print(f"Generador g encontrado: {g}")
        
        # Generar clave privada x (número aleatorio entre 2 y p-2)
        x = random.randint(2, p-2)
        print(f"Clave privada x generada")
        
        # Calcular clave pública y = g^x mod p
        y = pow(g, x, p)
        print(f"Clave pública y calculada: {y}")
        
        # Crear diccionarios con las claves
        clave_publica = {'p': p, 'g': g, 'y': y}
        clave_privada = x
        
        # Serializar a base64
        clave_publica_b64 = self._serializar_clave(clave_publica)
        clave_privada_b64 = self._serializar_clave(clave_privada)
        
        return clave_privada_b64, clave_publica_b64

    def cifrar(self, mensaje):
        """
        funcion:
        cifra un mensaje usando ElGamal
        
        atributos:
            mensaje: El mensaje a cifrar (str).
        
        devuelve:
            str: Mensaje cifrado en base64.
        """
        if not self.clave_publica:
            raise ValueError("Clave pública no configurada")
        
        p, g, y = self.clave_publica['p'], self.clave_publica['g'], self.clave_publica['y']
        
        # Convertir mensaje a número (simplificación: asumimos mensaje corto)
        m = int.from_bytes(mensaje.encode('utf-8'), 'big')
        if m >= p:
            raise ValueError("Mensaje demasiado largo para el primo p")
        
        # Generar clave efímera k
        k = random.randint(1, p-2)
        while sympy.gcd(k, p-1) != 1:
            k = random.randint(1, p-1)
        
        # Calcular c1 y c2
        c1 = pow(g, k, p)
        s = pow(y, k, p)
        c2 = (m * s) % p
        
        # Combinar en un diccionario y serializar
        cifrado = {'c1': c1, 'c2': c2}
        return self._serializar_clave(cifrado)

    def descifrar(self, mensaje_cifrado_b64):
        """
        funcion:
        descifra un mensaje cifrado usando ElGamal
        
        atributos:
            mensaje_cifrado_b64: El mensaje cifrado en base64 (str).
        
        devuelve:
            str: Mensaje descifrado.
        """
        if not self.clave_privada:
            raise ValueError("Clave privada no configurada")
        
        cifrado = self._deserializar_clave(mensaje_cifrado_b64)
        c1, c2 = cifrado['c1'], cifrado['c2']
        x = self.clave_privada
        p = self.clave_publica['p']
        
        # Calcular s^-1 mod p
        s = pow(c1, x, p)
        s_inv = pow(s, -1, p)
        
        # Recuperar mensaje
        m = (c2 * s_inv) % p
        
        # Convertir de número a string
        return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore')

    def ejecutar_cifrado_txt(self):
        """
        funcion:
        permite ingresar el mensaje a cifrar y guardarlo en un archivo .txt
        """
        mensaje = input("Ingrese el mensaje a cifrar: ")
        if not self.clave_publica:
            clave_publica_b64 = input("Ingrese la clave pública ElGamal (en base64): ")
            try:
                self.clave_publica = self._deserializar_clave(clave_publica_b64)
            except Exception as e:
                print(f"Error al cargar la clave pública: {e}")
                return
        if not self.clave_privada:
            # Generar par de claves si no existen
            print("Generando nuevo par de claves ElGamal")
            clave_privada_b64, clave_publica_b64 = self.generar_par_claves()
            self.clave_publica = self._deserializar_clave(clave_publica_b64)
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
        print("Leyendo archivo cifrado...")
        mensaje_cifrado = t.leer_txt()
        if mensaje_cifrado is None:
            print("No se pudo leer el mensaje cifrado del archivo TXT.")
            return
        
        if not self.clave_privada:
            clave_input = input("Ingrese su clave privada ElGamal (en base64) o el nombre del archivo: ")
            
            # Verificar si es un archivo
            try:
                with open(clave_input, 'r', encoding='utf-8') as f:
                    clave_privada_b64 = f.read().strip()
                print("Clave privada leída desde archivo")
            except:
                # Si no es archivo, asumir que es la clave directamente
                clave_privada_b64 = clave_input
                print("Clave privada ingresada directamente")
            
            while True:
                try:
                    self.clave_privada = self._deserializar_clave(clave_privada_b64)
                    print("Clave privada cargada exitosamente")
                    break
                except Exception as e:
                    print("Error al cargar la clave privada. Inténtelo de nuevo.")
                    clave_input = input("Ingrese su clave privada ElGamal (en base64) o el nombre del archivo: ")
                    try:
                        with open(clave_input, 'r', encoding='utf-8') as f:
                            clave_privada_b64 = f.read().strip()
                        print("Clave privada leída desde archivo")
                    except:
                        clave_privada_b64 = clave_input
                        print("Clave privada ingresada directamente")
                        continue
        while True:
            try:
                print("Descifrando mensaje...")
                mensaje_descifrado = self.descifrar(mensaje_cifrado)
                print("Mensaje descifrado exitosamente")
                print("\n" + "="*40)
                print("MENSAJE DESCIFRADO:")
                print("="*40)
                print(mensaje_descifrado)
                print("="*40)
                break
            except Exception as e:
                print("La clave es incorrecta o hay un error en el descifrado. Inténtelo de nuevo.")
                clave_input = input("Ingrese su clave privada ElGamal (en base64) o el nombre del archivo: ")
                try:
                    with open(clave_input, 'r', encoding='utf-8') as f:
                        clave_privada_b64 = f.read().strip()
                    print("Clave privada leída desde archivo")
                except:
                    clave_privada_b64 = clave_input
                    print("Clave privada ingresada directamente")
                while True:
                    try:
                        self.clave_privada = self._deserializar_clave(clave_privada_b64)
                        print("Clave privada cargada exitosamente")
                        break
                    except Exception as e:
                        print("Error al cargar la clave privada. Inténtelo de nuevo.")
                        clave_input = input("Ingrese su clave privada ElGamal (en base64) o el nombre del archivo: ")
                        try:
                            with open(clave_input, 'r', encoding='utf-8') as f:
                                clave_privada_b64 = f.read().strip()
                            print("Clave privada leída desde archivo")
                        except:
                            clave_privada_b64 = clave_input
                            print("Clave privada ingresada directamente")
                            continue