#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pruebas_matriz.py - Actividad 151: ejecuta la matriz de pruebas CP01-CP05.

Reutiliza las funciones de detector.py (sin subprocess) y por cada caso:
  * compara el estado observado de CADA regla con el esperado,
  * guarda la evidencia en evidencias/CPxx_resultado.json,
  * registra cualquier error SIN abortar la ejecucion.

ROBUSTEZ:
  * Cada caso se ejecuta aislado en try/except: un fixture faltante
    (FixtureError) o cualquier otra excepcion se registra como ERROR y la
    matriz CONTINUA con los casos restantes.
  * El resumen final se genera SIEMPRE (bloque finally), aunque algo falle.
  * CP04 exige NO_EVALUABLE causado por un fixture VALIDO con datos ausentes;
    un fixture inexistente produce ERROR, nunca NO_EVALUABLE.

RESULTADOS POSIBLES POR CASO:
  CUMPLE     el observado coincide con lo esperado
  NO CUMPLE  el observado difiere de lo esperado
  ERROR      el caso no pudo ejecutarse (p. ej. fixture inexistente)
  PENDIENTE  el caso requiere Windows (CP05) y este equipo no lo es

CODIGO DE SALIDA: 0 si no hay NO CUMPLE ni ERROR; 1 en caso contrario.

Uso:  python pruebas_matriz.py
"""
import csv
import json
import platform
import sys
from pathlib import Path

import detector

BASE = Path(__file__).resolve().parent
EVID = BASE / "evidencias"
DOCS = BASE / "documentacion"

R1, R2 = "R1_FIREWALL", "R2_SMBV1"

# (id, modo, fixture, {regla: estado esperado}, texto que debe aparecer en el detalle)
CASOS = [
    ("CP01", "FIXTURE", "seguro.json", {R1: detector.OK, R2: detector.OK}, None),
    ("CP02", "FIXTURE", "smb1_habilitado.json", {R1: detector.OK, R2: detector.ALERTA}, "SMBv1 habilitado"),
    ("CP03", "FIXTURE", "firewall_deshabilitado.json", {R1: detector.ALERTA, R2: detector.OK}, "deshabilitado"),
    ("CP04", "FIXTURE", "dato_ausente.json",
     {R1: detector.NO_EVALUABLE, R2: detector.NO_EVALUABLE}, "Dato ausente"),
    ("CP05", "REAL", "-", None, None),     # None = cualquier estado valido
]
ESTADOS_VALIDOS = {detector.OK, detector.ALERTA, detector.NO_EVALUABLE}


def texto_estados(resultados):
    """'R1_FIREWALL=OK, R2_SMBV1=ALERTA'"""
    return ", ".join(f"{r['regla']}={r['estado']}" for r in resultados)


def texto_esperado(esperado):
    if esperado is None:
        return "Estado real detectado"
    return ", ".join(f"{k}={v}" for k, v in esperado.items())


def verificar(resultados, esperado, texto_detalle):
    """Devuelve 'CUMPLE' o 'NO CUMPLE' comparando regla por regla."""
    por_regla = {r["regla"]: r for r in resultados}
    if esperado is None:                                   # CP05: cualquier estado valido
        return "CUMPLE" if all(r["estado"] in ESTADOS_VALIDOS for r in resultados) else "NO CUMPLE"
    for regla, estado in esperado.items():
        r = por_regla.get(regla)
        if r is None or r["estado"] != estado:
            return "NO CUMPLE"
    if texto_detalle:                                      # la causa debe ser la correcta
        causas = [por_regla[k]["detalle"] for k, v in esperado.items()
                  if v != detector.OK]
        if not any(texto_detalle.lower() in c.lower() for c in causas):
            return "NO CUMPLE"
    return "CUMPLE"


def guardar_evidencia(cid, contenido):
    """Escribe evidencias/CPxx_resultado.json; un fallo de escritura no aborta la matriz."""
    try:
        EVID.mkdir(exist_ok=True)
        (EVID / f"{cid}_resultado.json").write_text(
            json.dumps(contenido, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"  (aviso) no se pudo guardar la evidencia de {cid}: {exc}")


def ejecutar_caso(caso):
    """
    Ejecuta UN caso y devuelve la fila [Caso, Entrada, Esperado, Observado, Resultado].
    Nunca lanza excepciones: todo error se convierte en una fila ERROR.
    """
    cid, modo, entrada, esperado, texto_detalle = caso
    nombre_entrada = entrada if modo == "FIXTURE" else "REAL"
    try:
        if modo == "REAL" and platform.system() != "Windows":
            return [cid, nombre_entrada, texto_esperado(esperado),
                    "No ejecutado: requiere Windows", "PENDIENTE"]
        datos = detector.recolectar_real() if modo == "REAL" else detector.recolectar_fixture(entrada)
        resultados = detector.evaluar(datos)
        guardar_evidencia(cid, resultados)
        return [cid, nombre_entrada, texto_esperado(esperado),
                texto_estados(resultados), verificar(resultados, esperado, texto_detalle)]
    except detector.FixtureError as exc:                   # fixture faltante o ilegible
        guardar_evidencia(cid, {"caso": cid, "resultado": "ERROR", "error": str(exc)})
        return [cid, nombre_entrada, texto_esperado(esperado), f"ERROR de fixture: {exc}", "ERROR"]
    except Exception as exc:                               # cualquier imprevisto
        guardar_evidencia(cid, {"caso": cid, "resultado": "ERROR",
                                "error": f"{type(exc).__name__}: {exc}"})
        return [cid, nombre_entrada, texto_esperado(esperado),
                f"ERROR inesperado: {type(exc).__name__}: {exc}", "ERROR"]


def escribir_resumen(filas):
    """Genera matriz_pruebas.csv/.md y devuelve el texto del resumen. Se llama siempre."""
    cab = ["Caso", "Entrada", "Esperado", "Observado", "Resultado"]
    try:
        DOCS.mkdir(exist_ok=True)
        with open(DOCS / "matriz_pruebas.csv", "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(cab)
            w.writerows(filas)
        md = ["| " + " | ".join(cab) + " |", "|" + "---|" * len(cab)]
        md += ["| " + " | ".join(c.replace("|", "/") for c in fila) + " |" for fila in filas]
        (DOCS / "matriz_pruebas.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"(aviso) no se pudo escribir la matriz: {exc}")

    conteo = {k: sum(1 for f in filas if f[4] == k)
              for k in ("CUMPLE", "NO CUMPLE", "ERROR", "PENDIENTE")}
    lineas = ["", "=" * 60, "RESUMEN FINAL DE LA MATRIZ DE PRUEBAS", "=" * 60]
    lineas += [f"{f[0]}  {f[4]:<10}  {f[1]}" for f in filas]
    lineas += ["-" * 60,
               f"Total: {len(filas)} | CUMPLE: {conteo['CUMPLE']} | NO CUMPLE: {conteo['NO CUMPLE']} "
               f"| ERROR: {conteo['ERROR']} | PENDIENTE: {conteo['PENDIENTE']}"]
    for f in filas:
        if f[4] in ("ERROR", "NO CUMPLE"):
            lineas.append(f"  -> {f[0]}: {' '.join(f[3].split())[:150]}")
    return "\n".join(lineas), conteo


def main():
    filas = []
    faltantes = detector.fixtures_faltantes([c[2] for c in CASOS if c[1] == "FIXTURE"])
    if faltantes:
        print("AVISO: faltan fixtures: " + ", ".join(faltantes) +
              f"\n       Deben estar en la carpeta '{detector.DIR_FIXTURES}'. "
              "Los casos afectados se marcaran como ERROR y la matriz continuara.\n")
    conteo = {"NO CUMPLE": 0, "ERROR": 0}
    try:
        for caso in CASOS:                                 # un caso con error NO detiene a los demas
            fila = ejecutar_caso(caso)
            filas.append(fila)
            print(f"{fila[0]}: {fila[4]}")
    finally:                                               # el resumen se genera SIEMPRE
        resumen, conteo = escribir_resumen(filas)
        print(resumen)
    return 1 if (conteo["NO CUMPLE"] or conteo["ERROR"]) else 0


if __name__ == "__main__":
    sys.exit(main())
