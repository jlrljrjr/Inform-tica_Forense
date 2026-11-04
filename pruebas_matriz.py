#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pruebas_matriz.py - Actividad 151: ejecuta la matriz de pruebas CP01-CP05.

Reutiliza las funciones de detector.py (sin subprocess) y por cada caso:
  * compara el estado observado con el esperado,
  * guarda la evidencia en evidencias/CPxx_resultado.json,
  * genera documentacion/matriz_pruebas.md y documentacion/matriz_pruebas.csv.

CP05 (modo REAL) solo puede ejecutarse en Windows; en otro sistema queda
'PENDIENTE' y NO se inventa un resultado.

Uso:  python pruebas_matriz.py
"""
import csv
import json
import platform
from pathlib import Path

import detector

BASE = Path(__file__).resolve().parent
EVID = BASE / "evidencias"
DOCS = BASE / "documentacion"

# (id, modo, entrada, regla bajo prueba, estado esperado)
CASOS = [
    ("CP01", "FIXTURE", "seguro.json", None, detector.OK),
    ("CP02", "FIXTURE", "smb1_habilitado.json", "R2_SMBV1", detector.ALERTA),
    ("CP03", "FIXTURE", "firewall_deshabilitado.json", "R1_FIREWALL", detector.ALERTA),
    ("CP04", "FIXTURE", "dato_ausente.json", None, detector.NO_EVALUABLE),
    ("CP05", "REAL", "-", None, "Estado real detectado"),
]


def estados(resultados):
    return {r["regla"]: r["estado"] for r in resultados}


def verificar(caso, resultados):
    """Devuelve (observado, resultado) para un caso."""
    _, modo, _, regla, esperado = caso
    est = estados(resultados)
    if modo == "REAL":
        validos = {detector.OK, detector.ALERTA, detector.NO_EVALUABLE}
        ok = all(v in validos for v in est.values())
        return ", ".join(f"{k}={v}" for k, v in est.items()), "CUMPLE" if ok else "NO CUMPLE"
    # Con regla bajo prueba solo se exige esa regla; si no, ambas reglas.
    objetivo = {regla: est[regla]} if regla else est
    ok = all(v == esperado for v in objetivo.values())
    return ", ".join(f"{k}={v}" for k, v in est.items()), "CUMPLE" if ok else "NO CUMPLE"


def main():
    EVID.mkdir(exist_ok=True)
    DOCS.mkdir(exist_ok=True)
    filas = []
    for caso in CASOS:
        cid, modo, entrada, regla, esperado = caso
        if modo == "REAL" and platform.system() != "Windows":
            filas.append([cid, "REAL", esperado, "No ejecutado (equipo no Windows)", "PENDIENTE"])
            continue
        datos = detector.recolectar_real() if modo == "REAL" else detector.recolectar_fixture(entrada)
        resultados = detector.evaluar(datos)
        (EVID / f"{cid}_resultado.json").write_text(
            json.dumps(resultados, ensure_ascii=False, indent=2), encoding="utf-8")
        observado, veredicto = verificar(caso, resultados)
        esperado_txt = esperado if not regla else f"{regla}={esperado}"
        filas.append([cid, entrada if modo == "FIXTURE" else "REAL", esperado_txt, observado, veredicto])

    cab = ["Caso", "Entrada", "Esperado", "Observado", "Resultado"]
    with open(DOCS / "matriz_pruebas.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(cab)
        w.writerows(filas)
    md = ["| " + " | ".join(cab) + " |", "|" + "---|" * len(cab)]
    md += ["| " + " | ".join(fila) + " |" for fila in filas]
    (DOCS / "matriz_pruebas.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
