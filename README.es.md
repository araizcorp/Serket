<p align="center">
  <img src="serket/ui/assets/brand/serket-logo-primary-red-v3.png" alt="Serket por AraizCorp" width="520">
</p>

<h1 align="center">Serket</h1>

<p align="center">
  Inteligencia de relaciones y análisis de rutas de Active Directory.<br>
  Una herramienta de seguridad de doble uso y ejecución local creada por <strong>AraizCorp LLC</strong>.
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.es.md">Español</a> ·
  <a href="LEGAL.es.md">Aviso legal</a> · <a href="DOCKER.md">Guía de contenedores</a>
</p>

> [!WARNING]
> **Estado de desarrollo:** Serket es actualmente una versión preliminar en desarrollo activo. La colección principal, construcción del grafo, análisis de resultados, buscador universal y exploración interactiva de rutas funcionan, pero la cobertura todavía no es completa. No debe utilizarse como única base para una decisión de seguridad en producción.

Serket recopila metadatos autorizados de Active Directory mediante LDAP, transforma identidades y permisos en un grafo dirigido y muestra el resultado en un banco de trabajo de investigación propio. Está pensado para defensores, auditores y equipos red/purple que trabajen con autorización expresa y reglas de enfrentamiento definidas.

Serket no se presenta como “indetectable”. Su perfil de colección controlada reduce consultas innecesarias, mide la huella de la colección y permite comparar la actividad esperada con la telemetría del DC, SIEM, EDR y NDR.

![Serket Workbench](docs/media/serket-workbench-preview-02.png)

## Estado de las funciones

| Función | Estado | Alcance actual |
|---|---:|---|
| Colección LDAP/DC-only | Disponible | Usuarios, grupos, sistemas, dominio, jerarquía OU/contenedores, GPO, trusts, permisos de propietario+DACL y AD CS |
| Clasificación de sistemas | Disponible | Estaciones, servidores miembro y controladores de dominio se modelan y cuentan por separado |
| Autenticación | Disponible | Contraseña, hash NTLM, caché Kerberos y LDAPS opcional |
| Grafo de relaciones | Disponible | Multigrafo dirigido; conserva permisos paralelos sin que uno sobrescriba a otro |
| Rutas globales | Disponible | Dijkstra ponderado hacia objetos de alto valor |
| Consulta interactiva | Disponible | Origen concreto hacia un destino o Tier 0 usando el grafo cargado |
| Buscador universal | Disponible | Nombre, SID, UPN, DN, DNS y `sAMAccountName` |
| Inspector | Disponible | Controla, controlado por, membresías, rutas, evidencia, impacto y corrección |
| Workbench local | Disponible | Resumen, Rutas, Explorer, Superficie y Detección; inglés por defecto y español opcional |
| Docker | Preparado | Imagen endurecida, Compose y publicación GHCR multi-arquitectura |
| AD CS | Parcial | Clasificación automática de ESC1 |
| Trusts | Parcial | Enumeración sin inferencias avanzadas de abuso |
| Detección | Parcial | Guía y telemetría esperada; todavía sin importación de evidencia SIEM/EDR |
| Paquete de colección | Disponible | Manifiesto y JSON separados para identidades, sistemas, permisos, estructura, AD CS, grafo y análisis |

## Prueba rápida con datos sintéticos

El laboratorio incluido contiene identidades ficticias de `LAB.SERKET.LOCAL` y no se conecta a ningún controlador de dominio.

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
serket --serve demo/serket-demo.json
```

### Linux o macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
serket --serve demo/serket-demo.json
```

Abre <http://127.0.0.1:8080>. El modo nativo escucha únicamente en loopback.

## Instalación

Serket requiere Python 3.10 o posterior. La instalación crea el comando `serket`; después de instalarlo no es necesario ejecutar la herramienta con `python serket.py`.

### Kali Linux, Linux y macOS

```bash
git clone https://github.com/araizcorp/Serket.git
cd Serket
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
hash -r
serket --help
```

En Kali o cualquier otra distribución Linux, **no utilices `py -m pip install .`**. `py` es el lanzador de Python de Windows y en Linux puede corresponder a otro programa. Con el entorno virtual activo, utiliza `python -m pip install .` como se muestra arriba.

El comando `serket` funciona desde cualquier directorio mientras el entorno virtual esté activo. Para utilizarlo en otra terminal, vuelve a activar ese mismo entorno:

```bash
source /ruta/a/Serket/.venv/bin/activate
serket --help
```

Si ya tienes `pipx` instalado y quieres disponer de `serket` en el `PATH` de tu usuario sin activar el entorno virtual cada vez, ejecuta lo siguiente desde el repositorio clonado:

```bash
pipx install .
pipx ensurepath
```

Abre una terminal nueva después de `pipx ensurepath` y comprueba el comando con `serket --help`.

### Windows PowerShell

```powershell
git clone https://github.com/araizcorp/Serket.git
Set-Location Serket
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
serket --help
```

`py` se utiliza únicamente para crear el entorno en Windows. Si el lanzador no está disponible, sustituye ese primer `py` por `python`. Después de activar el entorno, utiliza `python -m pip` para instalar el paquete y el comando `serket` dentro del entorno activo.

## Recopilar un dominio autorizado

Es preferible omitir `-p` para introducir la contraseña mediante el prompt oculto:

```bash
serket \
  -d corp.local \
  -u auditor \
  --ldaps
```

Serket descubre automáticamente un controlador mediante los registros DNS SRV de Active Directory correspondientes al dominio indicado. Utiliza `-dc HOST` solo para anular el descubrimiento, seleccionar un controlador concreto o trabajar sin acceso al DNS de AD.

Kerberos:

```bash
export KRB5CCNAME=/tmp/auditor.ccache
serket -d corp.local -u auditor -k
```

Hash NTLM:

```bash
serket -d corp.local -u auditor --hashes :NT_HASH
```

Controles habituales:

```bash
serket \
  -d corp.local \
  -u auditor \
  --rate-limit 0.20 \
  --max-paths 50 \
  --no-adcs
```

| Opción | Función |
|---|---|
| `-dc HOST` | Anula el descubrimiento DNS automático y usa un controlador concreto |
| `--rate-limit SEC` | Espera entre páginas LDAP; por defecto `0.08` segundos |
| `--max-paths N` | Máximo de rutas globales guardadas |
| `--no-acls` | Omite propietario y DACL; es más rápido pero elimina relaciones importantes |
| `--no-adcs` | Omite la enumeración de plantillas de certificado |
| `--ldaps` | Usa LDAP sobre TLS en el puerto 636 |
| `-o DIR` | Selecciona el directorio de salida |
| `--quiet` | Suprime el progreso para ejecuciones automatizadas |

Las consultas de descriptores de ACL y ADCS solicitan automáticamente propietario y DACL mediante el control LDAP de descriptores de seguridad de Microsoft. No requieren ninguna opción ni dependencia adicional. `--no-acls` y `--no-adcs` se aplican realmente a la recopilación; no son simples filtros de visualización.

### Cobertura: LDAP/DC-only frente a datos de hosts

La ejecución estándar de Serket es una recopilación LDAP/DC-only. Cubre la parte de estructura del directorio esperable en un colector estilo BloodHound: propiedades de objetos, membresías de grupos de seguridad, trusts, jerarquía de OU/contenedores, enlaces GPO, permisos relevantes de propietario/DACL sobre usuarios, grupos, sistemas, GPO, OU, contenedores y dominio, además de los objetos AD CS actualmente soportados.

No contacta todos los equipos unidos al dominio. Por tanto, una ejecución estándar no afirma relaciones obtenidas desde hosts como `HasSession`, `AdminTo` local, `CanRDP`, `ExecuteDCOM`, `CanPSRemote` o `SQLAdmin`. Esas relaciones requieren SMB/RPC, registro o telemetría del host y otro perfil de autorización/ruido. Cada resultado registra esta diferencia en `coverage` para que la ausencia de una relación no se presente como prueba de que no existe. Es la distinción entre recopilación de directorio/DC-only y de equipos documentada en los [métodos de colección de SharpHound](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound-flags).

Consulta todas las opciones con `serket --help`. El acceso heredado mediante `python serket.py` sigue disponible desde una copia del código fuente.

## Resultados y análisis

La ubicación predeterminada es `~/.serket/results/`. Cada ejecución crea un directorio:

```text
serket_corp_local_YYYYMMDD_HHMMSS/
├── manifest.json
├── domain.json
├── users.json
├── groups.json
├── computers.json
├── directory_objects.json
├── gpos.json
├── trusts.json
├── permissions.json
├── adcs.json
├── summary.json
├── graph.json
├── analysis.json
└── report.txt
```

`manifest.json` declara el esquema y los componentes. La separación permite detectar una fase incompleta o anormalmente vacía y validar el paquete antes de unirlo en memoria. El grafo y las rutas siguen analizándose como un único conjunto lógico. Todo el directorio es evidencia sensible y debe conservarse unido.

`serket server`, `--load` y `--serve` aceptan el directorio o su `manifest.json`. Los JSON únicos de versiones anteriores siguen siendo compatibles.

### Abrir el resultado más reciente en el Workbench

Cuando termine la recopilación, inicia la interfaz web sin tener que localizar el paquete manualmente:

```bash
serket server
```

Este comando abre el resultado más reciente de `~/.serket/results/`. Para seleccionar el último resultado de un dominio concreto:

```bash
serket server -d corp.local
```

Utiliza `--port 9090` para elegir otro puerto local o `--output DIR` si guardaste la recopilación fuera del directorio predeterminado. El Workbench solo escucha en `127.0.0.1`.

### Ver un resultado en terminal

```bash
serket --load ~/.serket/results/serket_corp_local_YYYYMMDD_HHMMSS
```

### Abrir un paquete concreto en el Workbench

```bash
serket --serve ~/.serket/results/serket_corp_local_YYYYMMDD_HHMMSS --port 8080
```

Los componentes contienen metadatos, telemetría, estado de calidad y cobertura, objetos, permisos, grafo, superficie derivada y rutas calculadas. Deben tratarse como evidencia sensible del cliente.

Los resultados creados por la versión v2.0 inicial afectada, donde los SID binarios se guardaban como texto ilegible, se reparan en memoria al cargarlos. Esto restaura identificadores canónicos, clasificación estación/servidor/DC, marcado Tier 0 y rutas derivadas de membresías. No puede recuperar ACL que nunca fueron escritas en el archivo antiguo; ejecuta una recopilación nueva para disponer de todos los permisos de propietario/DACL.

## Uso del Workbench

1. **Resumen** muestra métricas del dominio, grafo y colección, recuentos separados de estaciones/servidores/DC, calidad de datos y rutas prioritarias.
2. **Buscar** localiza objetos por nombre parcial, SID, UPN, DN, DNS o `sAMAccountName`.
3. **Rutas** permite seleccionar un origen y un destino o todos los objetos Tier 0, filtrar relaciones y limitar saltos.
4. **Grafo enfocado** muestra únicamente la ruta seleccionada. Los rombos se pueden mover libremente y las conexiones se recolocan en tiempo real.
5. **Inspector** muestra propiedades, relaciones salientes y entrantes, membresías, rutas, evidencia, impacto, telemetría y corrección.
6. **Explorer** explora el entorno del objeto seleccionado sin intentar representar todo el dominio de una vez.
7. **Superficie** agrupa Kerberos, delegación, ACL, AD CS, SID history, LAPS, gMSA y trusts.
8. **Detección** diferencia expectativas documentadas de evidencia desconocida. “Desconocido” no significa “invisible”; significa que no se ha importado validación del SIEM/EDR.

El selector `EN / ES` cambia el idioma y solo guarda esa preferencia en el navegador.

## Cobertura actual

Cuando existe evidencia suficiente, Serket modela:

- Membresía directa y transitiva de grupos
- `Contains`, `GPLink` y control administrativo derivado sobre controladores de dominio
- `GenericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner` y `AllExtendedRights`
- `Owns`, `ForceChangePassword`, `AddMember` y `AddSelf`
- `AddKeyCredentialLink`, `AddAllowedToAct`, `WriteSPN` y `WriteAccountRestrictions`
- `GetChanges`, `GetChangesAll`, `GetChangesInFilteredSet` y `DCSync` derivado cuando existe la pareja necesaria
- Delegación no restringida, restringida y RBCD
- Identidades Kerberoastable y AS-REP roastable
- Rutas AD CS ESC1
- SID history e indicadores heurísticos en descripciones
- Indicadores de visibilidad de LAPS clásico y Windows LAPS
- Indicadores gMSA sin guardar el blob de contraseña administrada
- Trusts de dominio y determinados metadatos de GPO

Serket conserva varios permisos entre el mismo origen y destino. La evidencia no transitable, como un derecho de replicación aislado o una inscripción de certificado ordinaria, sigue visible en el inventario de permisos pero queda fuera del cálculo de rutas hasta que existan las condiciones de una relación transitable.

Estas relaciones no prueban que una acción se haya ejecutado o que vaya a funcionar. Cada ruta debe validarse dentro del alcance autorizado.

## Docker

Construcción local durante el desarrollo:

```bash
docker build --tag serket:dev .
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  serket:dev
```

También se puede utilizar `docker compose up --build`.

La publicación está preparada para `ghcr.io/araizcorp/serket`, pero el comando de descarga será válido únicamente después de publicar la primera versión etiquetada. Consulta [DOCKER.md](DOCKER.md).

## Seguridad y privacidad

- El servidor nativo escucha en `127.0.0.1`.
- La interfaz no usa CDN, Neo4j, analítica externa ni transmite resultados a AraizCorp.
- La API desactiva la caché y aplica cabeceras restrictivas.
- La interfaz es de solo lectura y nunca ejecuta comandos de validación.
- El colector registra búsquedas, páginas, entradas, duración y etapas.

Serket no sustituye la autorización, el plan de colección ni el control de cambios. Conserva y elimina los resultados según la política del encargo.

## Limitaciones y roadmap

Todavía no están completos:

- Recopilación desde hosts de sesiones y derechos locales (`HasSession`, `AdminTo` local, RDP, DCOM, PSRemote y administración SQL); el colector actual permanece intencionadamente en modo LDAP/DC-only
- Análisis automático AD CS ESC2–ESC8
- Conclusiones avanzadas de trusts, filtrado SID y quarantine
- Importación de evidencia SIEM/EDR y estado de detección verificado
- Reanudación de una colección interrumpida
- Paquetes portables `.serket` con verificación de integridad
- Validación de rendimiento en dominios grandes y más consultas predefinidas
- Centro de exportación web a PDF, Markdown y CSV

## Pruebas de desarrollo

```bash
python -B -m unittest discover -s tests -v
python -m py_compile serket.py serket/cli.py serket/server/api.py
node --check serket/ui/workbench.js
node --check serket/ui/path-graph-interactions.js
docker build --tag serket:dev .
```

La suite cubre SID y descriptores binarios, composición DCSync, permisos paralelos, clasificación de sistemas, rutas a controladores de dominio, recuperación de resultados antiguos, API, búsqueda e interfaz. Las pruebas unitarias no sustituyen la validación en un dominio de laboratorio autorizado.

## Uso responsable, licencia y propiedad

Utiliza Serket únicamente en sistemas propios o con autorización expresa y por escrito. El operador es responsable del alcance, horarios, reglas de enfrentamiento, cumplimiento legal y protección de los resultados.

Copyright © 2026 **AraizCorp LLC**. El código fuente se distribuye bajo la [licencia MIT](LICENSE). La licencia no concede derechos sobre los nombres, logotipos o identidad visual de Serket o AraizCorp. Lee el [aviso legal y de responsabilidad](LEGAL.es.md) antes de utilizarlo.
