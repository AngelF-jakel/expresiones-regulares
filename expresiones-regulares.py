"""
Extractor de información de logs de tráfico de red.

No importa el formato ni la estructura del archivo de log (Apache, Nginx,
firewall, formato personalizado, texto plano, etc.): el programa busca
cada patrón directamente en el contenido de cada línea, sin asumir un
orden de columnas fijo. Si el dato existe en la línea, se encuentra.

El usuario elige mediante un menú qué quiere buscar. Las opciones
corresponden a los patrones descritos en el índice: IPv4, Puerto,
Fecha y hora, Protocolo, MAC, Flags TCP, Bytes/longitud y Dominio/URL.
"""
import re

# ---------------------------------------------------------------------------
# 1. LOS PATRONES REGEX (uno por cada elemento del índice)
# ---------------------------------------------------------------------------
# Nota: cuando un patrón tiene un grupo de captura (paréntesis), re.findall
# devuelve solo lo que hay dentro del grupo. Cuando no tiene grupos,
# devuelve la coincidencia completa. Por eso algunos patrones capturan
# solo la parte "útil" (p. ej. el número de puerto) y otros no.

PATRONES = {
    "1": (
        "Dirección IPv4",
        # 4 grupos de 1 a 3 dígitos separados por punto.
        # Usamos (?:...) en vez de (...) para que findall devuelva
        # la IP completa y no solo el último grupo.
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ),
    "2": (
        "Puerto",
        # El puerto va pegado a una IP después de ":" (IP:puerto).
        # Esto funciona sin importar qué haya antes o después en la
        # línea, porque solo buscamos ese fragmento dentro del texto.
        # Capturamos solo el número de puerto (1 a 5 dígitos).
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:(\d{1,5})\b"),
    ),
    "3": (
        "Fecha y hora",
        # Fecha AAAA-MM-DD, un espacio, hora HH:MM:SS
        re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"),
    ),
    "4": (
        "Protocolo",
        # No es un patrón numérico, sino una lista de palabras posibles.
        re.compile(r"\b(?:TCP|UDP|ICMP|HTTP)\b"),
    ),
    "5": (
        "Dirección MAC",
        # 6 grupos de 2 caracteres hexadecimales, separados por : o -
        re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    ),
    "6": (
        "Flags TCP",
        # Palabras cortas dentro de corchetes, separadas por coma.
        # Capturamos solo el contenido, sin los corchetes.
        re.compile(r"\[([A-Z_]+(?:,[A-Z_]+)*)\]"),
    ),
    "7": (
        "Bytes / longitud del paquete",
        # Etiqueta fija (len=, bytes=, size=) seguida de dígitos.
        re.compile(r"(?:len|bytes|size)=\d+"),
    ),
    "8": (
        "Dominio / URL",
        # Empieza con http:// o https:// y sigue con caracteres sin espacio.
        re.compile(r"https?://\S+"),
    ),
}

def cargar_lineas():
    """
    Pide al usuario la ruta del archivo de log y lo abre. No importa el
    formato del archivo (Apache, Nginx, firewall, texto plano, etc.):
    solo se necesita que sea un archivo de texto legible. Si la ruta no
    existe, vuelve a preguntar.
    """
    while True:
        ruta_archivo = input("Ruta del archivo de log a analizar: ").strip()
        try:
            with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
                lineas = f.readlines()
            print(f"Archivo '{ruta_archivo}' cargado correctamente "
                  f"({len(lineas)} líneas).")
            return [linea.strip() for linea in lineas if linea.strip()]
        except FileNotFoundError:
            print(f"[Error] No se encontró el archivo '{ruta_archivo}'. Intenta de nuevo.\n")
        except OSError as error:
            print(f"[Error] No se pudo abrir el archivo: {error}\n")


def mostrar_menu():
    """Imprime las opciones disponibles, tomadas del índice."""
    print("\n=== ¿Qué deseas buscar en el log? ===")
    for clave, (nombre, _patron) in PATRONES.items():
        print(f"  {clave}. {nombre}")
    print("  0. Salir")


def buscar_en_log(lineas, patron, nombre):
    """
    Aplica el patrón elegido a cada línea del log y muestra las
    coincidencias encontradas, junto con el número de línea.
    """
    total_coincidencias = 0

    print(f"\n=== Resultados para: {nombre} ===")
    for numero_linea, linea in enumerate(lineas, start=1):
        coincidencias = patron.findall(linea)
        if coincidencias:
            total_coincidencias += len(coincidencias)
            valores = ", ".join(coincidencias)
            print(f"  Línea {numero_linea}: {valores}")

    if total_coincidencias == 0:
        print("  No se encontraron coincidencias.")
    else:
        print(f"\nTotal de coincidencias encontradas: {total_coincidencias}")


def elegir_opcion():
    """Pide al usuario una opción válida del menú (o '0' para salir)."""
    opcion = input("\nElige una opción: ").strip()

    if opcion == "0":
        return opcion

    if opcion not in PATRONES:
        print("Opción no válida, intenta de nuevo.")
        return None

    return opcion


# ---------------------------------------------------------------------------
# PROGRAMA PRINCIPAL
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    lineas_log = cargar_lineas()

    while True:
        mostrar_menu()
        opcion = elegir_opcion()

        if opcion == "0":
            print("\nSaliendo del programa...")
            break

        if opcion is None:
            continue

        nombre_patron, patron_regex = PATRONES[opcion]
        buscar_en_log(lineas_log, patron_regex, nombre_patron)