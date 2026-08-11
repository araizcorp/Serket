# Aviso legal, autorización y responsabilidad

**Producto:** Serket — Active Directory Relationship Intelligence  
**Titular:** AraizCorp LLC  
**Versión del aviso:** 2.0 — agosto de 2026

## 1. Naturaleza de la herramienta

Serket es software de seguridad de doble uso. Analiza relaciones, permisos y rutas de control en Active Directory. La misma evidencia puede apoyar auditorías defensivas, validaciones de detección y ejercicios autorizados de red team o purple team. AraizCorp no presenta la herramienta como exclusivamente defensiva u ofensiva, ni como indetectable.

## 2. Titularidad

Copyright © 2026 AraizCorp LLC.

Serket, su nombre, identidad visual, documentación de producto y elementos de marca son propiedad de AraizCorp LLC. El código fuente se distribuye conforme a la licencia MIT incluida en este repositorio. Esa licencia de software no concede derechos sobre marcas, nombres comerciales ni identidad visual de AraizCorp LLC.

## 3. Uso autorizado

Serket puede utilizarse para:

- auditorías de seguridad con autorización escrita;
- ejercicios de red team, purple team y validación de controles;
- defensa, investigación, formación y laboratorios controlados;
- análisis de sistemas propios de la persona operadora.

No debe utilizarse sobre sistemas, dominios, cuentas o datos ajenos sin permiso expreso, vigente y verificable del titular. Disponer de credenciales válidas o acceso técnico no sustituye la autorización.

## 4. Responsabilidad de la persona operadora

Antes de ejecutar Serket, la persona operadora debe:

- confirmar objetivo, alcance, horario y reglas de compromiso;
- usar únicamente cuentas y controladores de dominio incluidos en ese alcance;
- evaluar el impacto de las consultas LDAP y configurar una cadencia apropiada;
- respetar las leyes, contratos, políticas internas y obligaciones de privacidad aplicables;
- detener y comunicar cualquier acceso accidental fuera de alcance;
- revisar manualmente los hallazgos y plantillas de validación antes de usarlos o incluirlos en un informe.

La interfaz no ejecuta acciones sobre el dominio. Las plantillas mostradas son contexto para validaciones autorizadas y no sustituyen el criterio profesional.

## 5. Custodia y tratamiento de datos

Los resultados pueden contener nombres de cuentas, relaciones de confianza, permisos, rutas de control y otra información sensible de Active Directory. Quien use Serket debe:

- almacenar los resultados como evidencia confidencial;
- limitar el acceso al personal autorizado;
- evitar su envío a servicios externos no aprobados;
- aplicar cifrado, retención y eliminación conforme al encargo;
- eliminar o anonimizar datos cuando ya no sean necesarios.

La ejecución nativa se publica únicamente en `127.0.0.1`. El contenedor escucha internamente en todas sus interfaces para funcionar con Docker, pero la configuración distribuida publica el puerto solo en el loopback del host. Estas medidas reducen exposición y no sustituyen la seguridad del equipo.

## 6. Colección controlada y validación de detección

El perfil de colección controlada pretende evitar solicitudes innecesarias y producir evidencia reproducible. No implica ni garantiza que la actividad sea invisible o que no genere alertas.

La telemetría de colección documenta búsquedas, páginas, objetos, duración, transporte y etapas. Debe contrastarse con registros del controlador de dominio, SIEM, EDR/NDR y procedimientos del equipo responsable.

## 7. Limitaciones técnicas

Serket no garantiza cobertura completa de Active Directory ni clasificación automática de todos los vectores. Los límites conocidos se documentan en el README y en la interfaz. Un resultado ausente no demuestra que una relación o riesgo no exista.

## 8. Ausencia de garantía y limitación de responsabilidad

El software se proporciona conforme a la cláusula de ausencia de garantía de la licencia MIT. En la máxima medida permitida por la ley aplicable, AraizCorp LLC no asume responsabilidad por usos ilegales, no autorizados, negligentes o fuera de alcance, ni por decisiones tomadas sin validación profesional de los resultados.

## 9. Aceptación

La ejecución o uso de Serket implica que la persona operadora declara disponer de autorización suficiente, comprender la sensibilidad de los datos y asumir la responsabilidad de su uso dentro del alcance acordado.
