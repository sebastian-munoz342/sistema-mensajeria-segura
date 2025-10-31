"""se importan los modulos de cifrado y descifrado"""
import cifrado_ecc
import cifrado_rsa
import cifrado_elgamal
import cifrado_aes256
import cifrado_blowfish
import cifrado_des 

class SubMenuC:
    """Clase para manejar todos los submenús de cifrado y descifrado."""
    def __init__(self):
        self.menu_a = ('''
         ¿Qué método de cifrado deseas utilizar?\n
         Cifrados Asimetricos\n
         A) Cifrado ECC (curva Elíptica)    B) Cifrado RSA
         C) Cifrado ElGamal\n
         Cifrados Simetricos\n
         D) Cifrado AES 256                 E) Cifrado BlowFish
         F) Cifrado DES                     G) Volver al menú principal\n''')
        

    def ejecutar_menu_a(self, tipo_menu):
        """Función: Ejecuta el menú seleccionado según el tipo."""
        while True:
            if tipo_menu == "a":
                print(self.menu_a)
                opcion = input("Seleccione una opción: ").lower()
                if opcion == "a":
                    e = cifrado_ecc.CifradoECC()
                    e.ejecutar_cifrado_txt()
                elif opcion == "b":
                    r = cifrado_rsa.CifradoRSA()
                    r.ejecutar_cifrado_txt()
                elif opcion == "c":
                    eg = cifrado_elgamal.CifradoElGamal()
                    eg.ejecutar_cifrado_txt()
                elif opcion == "d":
                    a = cifrado_aes256.AESCifrado()
                    a.ejecutar_cifrado()
                elif opcion == "e":
                    b = cifrado_blowfish.BlowFishCifrado()
                    b.ejecutar_cifrado()
                elif opcion == "f":
                    d = cifrado_des.DESCifrado()
                    d.ejecutar_cifrado()
                elif opcion == "g":
                    return
                else:
                    print("Opción invalida. Por favor, intente nuevamente.")

