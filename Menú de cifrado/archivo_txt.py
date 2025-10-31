def crear_txt(mensaje_cifrado):
    """
    Función: permite crear un archivo .TXT con un nombre personalizado
        atributos:
            mensaje_cifrado: El mensaje cifrado que se desea guardar en el archivo TXT.
    """
    nombre_de_archivo_txt=input("Ingrese el nombre del archivo para crearlo (sin la extensión): ")
    nombre_de_archivo_txt += ".txt" #agrega la extension .txt al nombre_de_archivo

    # abre el archivo en modo escritura ('w') y codificación UTF-8.
    with open(nombre_de_archivo_txt, mode='w', newline='', encoding='utf-8') as archivo:
        archivo.write(mensaje_cifrado)
    print(f"El archivo '{nombre_de_archivo_txt}' ha sido creado con el mensaje cifrado.")


def leer_txt():
    """función: permite leer un archivo .txt con un nombre personalizado"""
    nombre_de_archivo_txt=input("Ingrese el nombre del archivo que desea leer (sin la extensión): ")
    nombre_de_archivo_txt += ".txt" #agrega la extension .txt al nombre_de_archivo

    try:
        # abre el archivo en modo lectura ('r') con codificación UTF-8.
        with open(nombre_de_archivo_txt, mode='r', encoding='utf-8') as archivo:
            contenido = archivo.read().strip()  # lee todo el contenido y quita espacios o saltos de línea

            if contenido:
                return contenido
            else:
                print("El archivo está vacío.")
                return   
                  
    #si el archivo no existe imprime este mensaje
    except FileNotFoundError:
        print(f"El archivo '{nombre_de_archivo_txt}' no se encuentra.")
        return 