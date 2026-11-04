#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.py - Actividad 150: Detector de configuraciones inseguras (Windows)

EJECUCION:
    python detector.py REAL
    python detector.py FIXTURE seguro.json
    python detector.py FIXTURE smb1_habilitado.json
    python detector.py FIXTURE firewall_deshabilitado.json
    python detector.py FIXTURE dato_ausente.json

REGLAS (unicamente estas dos):
    R1_FIREWALL : firewall habilitado en todos los perfiles de Windows
    R2_SMBV1    : protocolo SMBv1 deshabilitado

SOLO LECTURA:
    * No se ejecuta ningun comando que modifique configuracion
      (nada de Set-*, Enable-*, Disable-*, netsh ... set, reg add/delete).
    * Solo se usan cmdlets Get-* y lectura del registro con KEY_READ.
    * Lo unico que se escribe son los informes en la carpeta resultados/.

ARQUITECTURA (capas independientes y reutilizables):
    1) Recoleccion : modo REAL (consulta Windows) o modo FIXTURE (lee un JSON).
    2) Reglas      : R1 y R2 evaluan los datos; son las mismas en ambos modos.
    3) Exportacion : escribe resultado_detector.json y resultado_detector.csv.

CODIGOS DE SALIDA:
    0 = ejecucion correcta (aunque haya ALERTA o NO_EVALUABLE; son hallazgos)
    2 = error de uso o fixture ilegible (no se pudo ni empezar a evaluar)
"""

import argparse
import csv
import json
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# CONSTANTES
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent          # carpeta del proyecto
DIR_FIXTURES = BASE_DIR / "fixtures"                # fixtures por defecto
DIR_RESULTADOS = BASE_DIR / "resultados"            # salida de informes
ARCHIVO_JSON = "resultado_detector.json"
ARCHIVO_CSV = "resultado_detector.csv"
CAMPOS = ["regla", "estado", "detalle", "fecha_hora_ejecucion"]

OK = "OK"
ALERTA = "ALERTA"
NO_EVALUABLE = "NO_EVALUABLE"


class FixtureError(Exception):
    """El archivo fixture no existe, no es JSON valido o no es un objeto JSON."""


# --------------------------------------------------------------------------
# UTILIDADES COMUNES
# --------------------------------------------------------------------------
def a_booleano(valor):
    """
    Convierte valores de PowerShell/JSON a True, False o None.
    Acepta true/false, 1/0 y sus versiones en texto. Cualquier otro valor
    (None, 2 = NotConfigured, texto desconocido) devuelve None, porque con
    ellos NO se puede afirmar si algo esta habilitado o no.
    """
    texto = str(valor).strip().lower()
    if texto in ("true", "1"):
        return True
    if texto in ("false", "0"):
        return False
    return None


def dato(datos, error):
    """Formato interno unico de un dato recolectado: {'datos': ..., 'error': ...}."""
    return {"datos": datos, "error": error}


def ejecutar_powershell(comando, tiempo_max=30):
    """
    Ejecuta UN comando PowerShell de solo lectura y devuelve su salida.
    Lanza excepcion si falla; quien llama la convierte en NO_EVALUABLE.
    """
    resultado = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", comando],
        capture_output=True, text=True, timeout=tiempo_max,
    )
    if resultado.returncode != 0:
        raise RuntimeError(resultado.stderr.strip() or "PowerShell devolvio error")
    return resultado.stdout.strip()


# --------------------------------------------------------------------------
# MODO REAL: consulta el Windows local con operaciones de SOLO LECTURA
# --------------------------------------------------------------------------
def recolectar_firewall_real():
    """
    Dato para R1. Comando de solo lectura: Get-NetFirewallProfile.
    Devuelve {Domain: bool, Private: bool, Public: bool}. Se usa el cmdlet
    (y no 'netsh') porque su salida no depende del idioma de Windows.
    """
    try:
        salida = ejecutar_powershell(
            "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
        )
        crudo = json.loads(salida)
        if isinstance(crudo, dict):      # con un solo perfil PowerShell no devuelve lista
            crudo = [crudo]
        perfiles = {p["Name"]: a_booleano(p["Enabled"]) for p in crudo}
        if not perfiles:
            return dato(None, "No se obtuvieron perfiles de firewall")
        return dato(perfiles, None)
    except Exception as exc:             # cualquier fallo => NO_EVALUABLE
        return dato(None, f"{type(exc).__name__}: {exc}")


def recolectar_smb1_real():
    """
    Dato para R2.
    Metodo 1 (solo lectura): (Get-SmbServerConfiguration).EnableSMB1Protocol
              -> requiere consola como Administrador.
    Metodo 2 (solo lectura): winreg con KEY_READ sobre
              HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1
              (0 = deshabilitado, 1 = habilitado, ausente = no concluyente).
    Nunca se escribe en el registro.
    """
    try:
        valor = a_booleano(ejecutar_powershell(
            "(Get-SmbServerConfiguration).EnableSMB1Protocol"))
        if valor is not None:
            return dato(valor, None)
        error_ps = "Valor no interpretable"
    except Exception as exc:
        error_ps = f"{type(exc).__name__}: {exc}"

    try:
        import winreg                    # modulo exclusivo de Windows
        ruta = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ruta, 0, winreg.KEY_READ) as clave:
            valor_reg, _ = winreg.QueryValueEx(clave, "SMB1")
        valor = a_booleano(valor_reg)
        if valor is not None:
            return dato(valor, None)
        return dato(None, f"Valor SMB1 del registro no interpretable: {valor_reg}")
    except FileNotFoundError:
        return dato(None, f"{error_ps}; el valor SMB1 no existe en el registro "
                          "(se usa el valor por defecto de la version de Windows)")
    except Exception as exc:
        return dato(None, f"{error_ps}; registro: {type(exc).__name__}: {exc}")


def recolectar_real():
    """Reune los datos del equipo real. Solo funciona en Windows."""
    if platform.system() != "Windows":
        motivo = f"El modo REAL requiere Windows (sistema detectado: {platform.system()})"
        return {"firewall": dato(None, motivo), "smb1": dato(None, motivo)}
    return {"firewall": recolectar_firewall_real(), "smb1": recolectar_smb1_real()}


# --------------------------------------------------------------------------
# MODO FIXTURE: lee datos simulados desde un archivo JSON
# --------------------------------------------------------------------------
def localizar_fixture(nombre):
    """Busca el fixture tal como se escribio o dentro de la carpeta fixtures/."""
    candidatos = [Path(nombre), DIR_FIXTURES / nombre]
    for ruta in candidatos:
        if ruta.is_file():
            return ruta
    raise FixtureError(f"No se encontro el fixture '{nombre}' (se busco en: "
                       + ", ".join(str(c) for c in candidatos) + ")")


def recolectar_fixture(nombre):
    """
    MODO FIXTURE: carga el JSON y lo convierte al mismo formato interno que el
    modo REAL. No ejecuta comandos ni consulta el equipo.

    Formato esperado del fixture:
        {"firewall": {"Domain": true, "Private": true, "Public": true},
         "smb1": false}
    Una clave ausente, null o con tipo incorrecto NO rompe el programa: genera
    un dato con error, que la regla correspondiente marca NO_EVALUABLE.
    """
    ruta = localizar_fixture(nombre)
    try:
        with open(ruta, encoding="utf-8") as archivo:
            contenido = json.load(archivo)
    except json.JSONDecodeError as exc:
        raise FixtureError(f"El fixture '{ruta.name}' no es JSON valido: {exc}") from exc
    except OSError as exc:
        raise FixtureError(f"No se pudo leer '{ruta}': {exc}") from exc
    if not isinstance(contenido, dict):
        raise FixtureError(f"El fixture '{ruta.name}' debe contener un objeto JSON")

    # --- firewall ---
    fw = contenido.get("firewall")
    if fw is None:
        firewall = dato(None, "Dato ausente: el fixture no contiene 'firewall'")
    elif not isinstance(fw, dict) or not fw:
        firewall = dato(None, "Dato invalido: 'firewall' debe ser un objeto con perfiles")
    else:
        firewall = dato({k: a_booleano(v) for k, v in fw.items()}, None)

    # --- smb1 ---
    if "smb1" not in contenido:
        smb1 = dato(None, "Dato ausente: el fixture no contiene 'smb1'")
    else:
        valor = a_booleano(contenido["smb1"])
        smb1 = dato(valor, None if valor is not None
                    else "Dato ausente o invalido: 'smb1' es null o no es booleano")

    return {"firewall": firewall, "smb1": smb1}


# --------------------------------------------------------------------------
# REGLAS: reciben un dato y devuelven (estado, detalle). No consultan nada.
# --------------------------------------------------------------------------
def regla_r1_firewall(entrada):
    """
    R1 - FIREWALL
        Todos los perfiles habilitados ........ OK
        Algun perfil deshabilitado ............ ALERTA (tiene prioridad)
        Sin datos / perfil indeterminado ...... NO_EVALUABLE
    """
    perfiles = entrada["datos"]
    if perfiles is None:
        return NO_EVALUABLE, f"No se pudo evaluar el firewall: {entrada['error']}"
    apagados = [n for n, activo in perfiles.items() if activo is False]
    dudosos = [n for n, activo in perfiles.items() if activo is None]
    if apagados:
        return ALERTA, "Firewall deshabilitado en el perfil: " + ", ".join(apagados)
    if dudosos:
        return NO_EVALUABLE, "Estado indeterminado en el perfil: " + ", ".join(dudosos)
    return OK, "Firewall habilitado en todos los perfiles (" + ", ".join(perfiles) + ")"


def regla_r2_smbv1(entrada):
    """
    R2 - SMBV1
        Deshabilitado ......... OK
        Habilitado ............ ALERTA
        Sin datos ............. NO_EVALUABLE
    """
    habilitado = entrada["datos"]
    if habilitado is None:
        return NO_EVALUABLE, f"No se pudo evaluar SMBv1: {entrada['error']}"
    if habilitado:
        return ALERTA, "SMBv1 habilitado (protocolo obsoleto y vulnerable)"
    return OK, "SMBv1 deshabilitado"


REGLAS = (("R1_FIREWALL", regla_r1_firewall, "firewall"),
          ("R2_SMBV1", regla_r2_smbv1, "smb1"))


def evaluar(datos):
    """Aplica R1 y R2. Una sola marca de tiempo ISO 8601 para toda la corrida."""
    marca = datetime.now().isoformat(timespec="seconds")
    resultados = []
    for nombre, regla, clave in REGLAS:
        estado, detalle = regla(datos[clave])
        resultados.append({"regla": nombre, "estado": estado, "detalle": detalle,
                           "fecha_hora_ejecucion": marca})
    return resultados


# --------------------------------------------------------------------------
# EXPORTACION: JSON y CSV (las unicas escrituras del programa)
# --------------------------------------------------------------------------
def exportar(resultados, carpeta=DIR_RESULTADOS):
    """Genera resultado_detector.json y resultado_detector.csv en 'carpeta'."""
    carpeta = Path(carpeta)
    carpeta.mkdir(parents=True, exist_ok=True)
    ruta_json = carpeta / ARCHIVO_JSON
    ruta_csv = carpeta / ARCHIVO_CSV
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(resultados, f, ensure_ascii=False, indent=2)
    # utf-8-sig: Excel reconoce los acentos al abrir el CSV
    with open(ruta_csv, "w", encoding="utf-8-sig", newline="") as f:
        escritor = csv.DictWriter(f, fieldnames=CAMPOS)
        escritor.writeheader()
        escritor.writerows(resultados)
    return ruta_json, ruta_csv


# --------------------------------------------------------------------------
# PUNTO DE ENTRADA
# --------------------------------------------------------------------------
def analizar_argumentos(argv):
    parser = argparse.ArgumentParser(
        description="Detector de configuraciones inseguras (solo lectura).")
    parser.add_argument("modo", type=str.upper, choices=["REAL", "FIXTURE"],
                        help="REAL consulta Windows; FIXTURE usa un archivo JSON simulado")
    parser.add_argument("fixture", nargs="?",
                        help="archivo fixture (obligatorio en modo FIXTURE), p. ej. seguro.json")
    args = parser.parse_args(argv)
    if args.modo == "FIXTURE" and not args.fixture:
        parser.error("el modo FIXTURE requiere un archivo, p. ej.: FIXTURE seguro.json")
    if args.modo == "REAL" and args.fixture:
        parser.error("el modo REAL no admite archivo fixture")
    return args


def main(argv=None):
    args = analizar_argumentos(argv)
    try:
        datos = recolectar_real() if args.modo == "REAL" else recolectar_fixture(args.fixture)
    except FixtureError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    resultados = evaluar(datos)
    ruta_json, ruta_csv = exportar(resultados)

    origen = args.modo + (f" ({args.fixture})" if args.fixture else "")
    print(f"Modo de ejecucion: {origen}")
    for r in resultados:
        print(f"  [{r['estado']:<12}] {r['regla']}: {r['detalle']}")
    print(f"Resultados exportados a:\n  {ruta_json}\n  {ruta_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
