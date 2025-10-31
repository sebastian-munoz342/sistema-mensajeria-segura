"""se importan los modulos de cifrado y descifrado"""
import cifrado_ecc
import cifrado_rsa
import cifrado_elgamal
import cifrado_aes256
import cifrado_blowfish
import cifrado_des

class SubMenuD:
    """Clase para manejar todos los submenús de cifrado y descifrado."""
    def __init__(self):
        self.menu_c = ('''
         ¿Qué método de descifrado deseas utilizar?\n
         Descifrados Asimetricos\n
         A) Descifrado ECC (curva Elíptica)    B) Descifrado RSA
         C) Descifrado ElGamal\n
         Descifrados Simetricos\n
         D) Descifrado AES 256                 E) Descifrado BlowFish
         F) Descifrado DES                     G) Volver al menú principal\n''')

    def ejecutar_menu_c(self, tipo_menu):
        """Función: Ejecuta el menú seleccionado según el tipo."""
        while True:
            if tipo_menu == "c":
                print(self.menu_c)
                opcion = input("Seleccione una opción: ").lower()
                if opcion == "a":
                    e = cifrado_ecc.CifradoECC()
                    e.ejecutar_descifrado_txt()
                elif opcion == "b":
                    r = cifrado_rsa.CifradoRSA()
                    r.ejecutar_descifrado_txt()
                elif opcion == "c":
                    eg = cifrado_elgamal.CifradoElGamal()
                    eg.ejecutar_descifrado_txt()
                elif opcion == "d":
                    a = cifrado_aes256.AESCifrado()
                    a.ejecutar_descifrado()
                elif opcion == "e":
                    b = cifrado_blowfish.BlowFishCifrado()
                    b.ejecutar_descifrado()
                elif opcion == "f":
                    d = cifrado_des.DESCifrado()
                    d.ejecutar_descifrado()
                elif opcion == "g":
                    return
                else:
                    print("Opción invalida. Por favor, intente nuevamente.")
