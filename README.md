# P13 – Detector de configuraciones inseguras (Actividades 150 a 152)

Prototipo en Python que revisa dos configuraciones de seguridad de Windows **sin modificar nada**
(solo lectura) y exporta los hallazgos a JSON y CSV.

## Requisitos
- Python 3.8 o superior (solo biblioteca estándar; no hay que instalar paquetes).
- Modo REAL: Windows 10/11 con PowerShell. Para evaluar SMBv1 conviene abrir la consola **como Administrador**.
- Modo FIXTURE y pruebas: funcionan en cualquier sistema operativo.

## Instalación
1. Descarga o clona la carpeta `P13_Repositorio`.
2. Abre una terminal dentro de esa carpeta. No hay nada más que instalar.

## Ejecución
```
python detector.py REAL
python detector.py FIXTURE seguro.json
python detector.py FIXTURE smb1_habilitado.json
python detector.py FIXTURE firewall_deshabilitado.json
python detector.py FIXTURE dato_ausente.json
python pruebas_matriz.py        # ejecuta la matriz CP01-CP05 y guarda evidencias
```
Los informes se escriben en `resultados/resultado_detector.json` y `resultados/resultado_detector.csv`
(cada ejecución sobrescribe los anteriores). Códigos de salida: `0` ejecución correcta,
`2` error de uso o fixture inexistente/ilegible.

## Reglas
| Regla | OK | ALERTA | NO_EVALUABLE |
|---|---|---|---|
| **R1_FIREWALL** | Firewall habilitado en todos los perfiles (Domain, Private, Public) | Algún perfil deshabilitado | No se pudo consultar o hay un perfil indeterminado |
| **R2_SMBV1** | SMBv1 deshabilitado | SMBv1 habilitado | No se pudo determinar (sin permisos, dato ausente) |

Cada resultado tiene los campos `regla`, `estado`, `detalle` y `fecha_hora_ejecucion` (ISO 8601).

## Mensajes y detalle técnico
- **Consola:** mensajes cortos de una línea (por ejemplo, "Fallo de consulta CIM/WMI (servicio no disponible o sin permisos)" en lugar de la excepción completa de PowerShell).
- **JSON:** además de los cuatro campos, cada resultado incluye `detalle_tecnico` con `datos_evaluados` y el `error_tecnico` completo, sin recortar.
- **CSV:** solo los cuatro campos básicos.

## Fixtures obligatorios
La carpeta `fixtures/` debe estar junto a `detector.py` y contener `seguro.json`, `smb1_habilitado.json`,
`firewall_deshabilitado.json` y `dato_ausente.json`. Si falta alguno, el detector lo informa con un mensaje claro
(código de salida 2) y `pruebas_matriz.py` lo marca como `ERROR` y continúa con los demás casos.

## Matriz de pruebas
`python pruebas_matriz.py` ejecuta CP01 a CP05, aísla cada caso (un error no detiene a los demás) y siempre imprime
un resumen final y escribe `documentacion/matriz_pruebas.md/.csv`. Estados: `CUMPLE`, `NO CUMPLE`, `ERROR`
(caso no ejecutable, p. ej. fixture inexistente) y `PENDIENTE` (CP05 en un equipo que no es Windows).
Código de salida: 0 si no hay `NO CUMPLE` ni `ERROR`; 1 en caso contrario.

## Garantía de solo lectura
Solo se usan `Get-NetFirewallProfile`, `Get-SmbServerConfiguration` y lectura del registro con
`KEY_READ`. No hay `Set-*`, `Enable-*`, `Disable-*`, `netsh ... set` ni escritura en el registro.
Lo único que el programa escribe son los informes de `resultados/` y, en `pruebas_matriz.py`, las evidencias.

## Estructura del proyecto
```
P13_Repositorio/
├── README.md
├── detector.py             # detector (REAL / FIXTURE, reglas R1 y R2, exportación)
├── pruebas_matriz.py       # automatiza la matriz de pruebas CP01-CP05
├── fixtures/               # datos simulados (seguro, smb1_habilitado, firewall_deshabilitado, dato_ausente)
├── resultados/             # resultado_detector.json y .csv
├── evidencias/             # salidas por caso de prueba (CPxx_resultado.json, CPxx_consola.txt) y capturas
└── documentacion/          # matriz de pruebas, hallazgos, anexos, guion de defensa, preguntas, informe .docx
```

## Formato de un fixture
```json
{"firewall": {"Domain": true, "Private": true, "Public": false}, "smb1": false}
```
Una clave ausente o `null` no rompe el programa: la regla afectada queda `NO_EVALUABLE`.
