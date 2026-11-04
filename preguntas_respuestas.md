# Tres preguntas probables del profesor

**1. ¿Cómo garantizan que el detector trabaja en modo de solo lectura?**
Solo se invocan cmdlets de consulta (`Get-NetFirewallProfile`, `Get-SmbServerConfiguration`) y el registro se abre con el permiso `KEY_READ`, que impide escribir aunque hubiera un error. No hay `Set-*`, `Enable-*`, `Disable-*` ni `reg add`; se puede comprobar buscando esos términos en el código. Lo único que se escribe son los informes JSON/CSV en `resultados/`, que no forman parte de la configuración del sistema. Desde la perspectiva forense, esto reduce la alteración del sistema examinado.

**2. ¿Por qué existe el estado NO_EVALUABLE en lugar de devolver OK o ALERTA cuando falla una consulta?**
Porque un fallo (falta de privilegios, valor inexistente, sistema no Windows) no prueba que la configuración sea segura ni insegura. Devolver OK daría una falsa sensación de seguridad; devolver ALERTA generaría falsos positivos. NO_EVALUABLE distingue la ausencia de evidencia de la evidencia de ausencia y, con el campo `detalle`, indica la causa para diagnosticarla. Un ejemplo es el caso CP04, donde el fixture no tiene la clave `firewall`.

**3. ¿Qué valida realmente el modo FIXTURE y qué no? ¿Por qué no basta con probar en REAL?**
FIXTURE valida la lógica de las reglas: el REAL y el FIXTURE producen el mismo formato interno y pasan por las mismas funciones R1 y R2, así que cada rama (OK, ALERTA, NO_EVALUABLE) se prueba de forma reproducible. En REAL solo se observa el estado del equipo de ese momento, que no se puede forzar sin modificarlo. Lo que FIXTURE no valida es la recolección: que los comandos funcionen en cada versión de Windows. Para eso existe el caso CP05 en REAL, con verificación cruzada contra PowerShell.
