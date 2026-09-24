"""
Extractor de información de logs de tráfico de red.

Lee un archivo .log con formato estilo Apache/Nginx (formato "combined")
y extrae: IP, fecha/hora, método HTTP, ruta solicitada, código de estado,
tamaño de respuesta y user-agent.

Ejemplo de línea de log que este programa espera:
192.168.1.10 - - [15/Mar/2024:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 5324 "-" "Mozilla/5.0"
"""
import re
from collections import Counter

# ---------------------------------------------------------------------------
# 1. EL PATRÓN REGEX
# ---------------------------------------------------------------------------
# Usamos grupos con nombre (?P<nombre>...) para que sea fácil leer el
# resultado después, en vez de acordarnos de "el grupo 3" o "el grupo 5".
PATRON_LOG = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'      # IP del cliente
    r'\S+\s+\S+\s+'                                        # dos campos que casi siempre son "-"
    r'\[(?P<fecha>[^\]]+)\]\s+'                             # fecha entre corchetes [15/Mar/2024:...]
    r'"(?P<metodo>[A-Z]+)\s+'                               # método HTTP: GET, POST, etc.
    r'(?P<ruta>\S+)\s+'                                     # ruta solicitada: /index.html
    r'[^"]*"\s+'                                            # el resto de la línea de request (HTTP/1.1)
    r'(?P<codigo>\d{3})\s+'                                 # código de estado: 200, 404, etc.
    r'(?P<tamano>\d+|-)\s*'                                 # tamaño de la respuesta en bytes
    r'"(?P<referer>[^"]*)"\s*'                               # referer (opcional, puede ir vacío)
    r'"(?P<user_agent>[^"]*)"'                               # user-agent del cliente
)


def leer_log(ruta_archivo):
    """
    Lee el archivo línea por línea y devuelve una lista de diccionarios
    con la información extraída de cada línea que coincida con el patrón.

    Usamos re.finditer/match línea por línea (no findall sobre todo el
    archivo de una vez) para poder saber también qué líneas NO coincidieron,
    lo cual es útil para depurar logs con formato irregular.
    """
    registros = []
    lineas_no_reconocidas = 0

    with open(ruta_archivo, "r", encoding="utf-8") as f:
        for numero_linea, linea in enumerate(f, start=1):
            linea = linea.strip()
            if not linea:
                continue

            coincidencia = PATRON_LOG.match(linea)

            if coincidencia:
                # .groupdict() nos da un diccionario listo:
                # {'ip': '...', 'fecha': '...', 'metodo': '...', ...}
                datos = coincidencia.groupdict()
                datos["linea"] = numero_linea
                registros.append(datos)
            else:
                lineas_no_reconocidas += 1
                print(f"[Aviso] Línea {numero_linea} no coincide con el patrón esperado")

    print(f"\nTotal de líneas procesadas correctamente: {len(registros)}")
    print(f"Total de líneas no reconocidas: {lineas_no_reconocidas}\n")

    return registros


def generar_estadisticas(registros):
    """
    Genera un resumen simple a partir de los registros extraídos:
    IPs más frecuentes, códigos de estado más comunes y métodos HTTP usados.
    """
    ips = Counter(r["ip"] for r in registros)
    codigos = Counter(r["codigo"] for r in registros)
    metodos = Counter(r["metodo"] for r in registros)

    print("=== IPs con más peticiones ===")
    for ip, cantidad in ips.most_common(5):
        print(f"  {ip}: {cantidad} peticiones")

    print("\n=== Códigos de estado encontrados ===")
    for codigo, cantidad in codigos.most_common():
        print(f"  {codigo}: {cantidad} veces")

    print("\n=== Métodos HTTP usados ===")
    for metodo, cantidad in metodos.most_common():
        print(f"  {metodo}: {cantidad} veces")


def buscar_errores(registros):
    """
    Filtra y muestra solo las peticiones con código de error
    (4xx = error del cliente, 5xx = error del servidor).
    """
    patron_error = re.compile(r"^[45]\d{2}$")  # empieza con 4 o 5, seguido de 2 dígitos

    errores = [r for r in registros if patron_error.match(r["codigo"])]

    print(f"\n=== Peticiones con error ({len(errores)} encontradas) ===")
    for e in errores:
        print(f"  Línea {e['linea']}: {e['ip']} -> {e['metodo']} {e['ruta']} "
              f"[{e['codigo']}] el {e['fecha']}")

    return errores


def exportar_ips_unicas(registros, ruta_salida):
    """
    Guarda en un archivo de texto la lista de IPs únicas encontradas,
    ordenadas alfabéticamente. Útil, por ejemplo, para pasarlas a una
    lista de bloqueo o para análisis posterior.
    """
    ips_unicas = sorted(set(r["ip"] for r in registros))

    with open(ruta_salida, "w", encoding="utf-8") as f:
        for ip in ips_unicas:
            f.write(ip + "\n")

    print(f"\nSe exportaron {len(ips_unicas)} IPs únicas a: {ruta_salida}")


# ---------------------------------------------------------------------------
# PROGRAMA PRINCIPAL
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ARCHIVO_LOG = "trafico.log"
    ARCHIVO_SALIDA_IPS = "ips_unicas.txt"

    registros = leer_log(ARCHIVO_LOG)

    if registros:
        generar_estadisticas(registros)
        buscar_errores(registros)
        exportar_ips_unicas(registros, ARCHIVO_SALIDA_IPS)
    else:
        print("No se encontraron registros válidos en el archivo.")