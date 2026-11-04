# Guion de defensa oral (8 a 10 minutos)

> Los minutos 2-5 dependen de lo que hiciste en las Actividades 145 a 149; completa los corchetes con tus resultados reales.

**Minuto 1 – Introducción**
"Buenos días. Soy [nombre], del equipo [XX]. Presento la Práctica 13: un recorrido que va del análisis de una aplicación web y un entorno virtualizado hasta un detector de configuraciones inseguras. Mostraré qué hicimos, cómo lo validamos y qué aprendimos. El hilo conductor es la evidencia obtenida de forma reproducible y sin alterar el sistema examinado."

**Minuto 2-3 – Análisis web**
- Objetivo del análisis y sitio o aplicación revisada: [COMPLETAR].
- Metodología y herramientas usadas (por ejemplo, cabeceras HTTP, certificados, herramientas del navegador): [COMPLETAR].
- Hallazgos principales y una captura representativa: [COMPLETAR].
- Idea de cierre: "Documentamos lo observado sin modificar el objetivo."

**Minuto 4-5 – VirtualBox**
- Para qué se usó la máquina virtual: aislar el análisis y poder restaurar un estado limpio con instantáneas [COMPLETAR con tu configuración: sistema invitado, red, instantáneas].
- Qué se verificó dentro de la VM: [COMPLETAR].
- Idea de cierre: "El entorno virtual permite repetir las pruebas sin riesgo para el equipo anfitrión."

**Minuto 6-7 – Detector**
1. Mostrar la estructura: recolección, reglas, exportación.
2. Ejecutar `python detector.py FIXTURE seguro.json` y luego `firewall_deshabilitado.json`: explicar OK frente a ALERTA.
3. Ejecutar `dato_ausente.json`: explicar NO_EVALUABLE ("ausencia de evidencia no es evidencia de seguridad").
4. Ejecutar `python detector.py REAL` (o mostrar la captura) y comparar con `Get-NetFirewallProfile`.
5. Mostrar `resultado_detector.json` y `.csv`, y la matriz CP01-CP05 con sus resultados.
6. Subrayar: solo lectura, sin Set-*, sin escritura en el registro.

**Minuto 8-10 – Conclusiones**
- Se cumplió el objetivo: detector funcional en modos REAL y FIXTURE, con matriz de pruebas CP01-CP05.
- Aprendizajes: separar recolección y reglas permite probar la lógica sin depender del equipo; el estado NO_EVALUABLE evita falsos OK.
- Limitaciones: solo dos reglas, SMBv1 puede requerir administrador, los fixtures son simulados.
- Trabajo futuro: más reglas, hash SHA-256 de los informes, ejecución en varios equipos.
- Cierre: "Gracias; quedo atento a sus preguntas."
