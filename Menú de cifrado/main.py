import sys
import submenus_cifrar as SC
import submenus_descifrar as SD
def ejecutar_menu():
    texto_menu = ("""
        Bienvenido a la aplicación de Cifrado 

        a) Crear y cifrar un archivo de texto
        b) Descifrar un archivo de texto
        c) Salir del programa""")

    while True:
        print(texto_menu)
        opcion = input("\nSeleccione una opción: ").lower()
        if opcion == "a":
            sma = SC.SubMenuC()
            sma.ejecutar_menu_a("a")
        elif opcion == "b":
            smc = SD.SubMenuD()
            smc.ejecutar_menu_c("c")
        elif opcion == "c":
            print("Has salido del menú")
            sys.exit()
        else:
            print("Opción no válida. Por favor, intente nuevamente.")

ejecutar_menu()