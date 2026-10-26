# USENIX Security 2027 ciclo 2: adecuación del manuscrito

Fecha de consulta: 2026-10-20. Venue de referencia para preparar un borrador en inglés; no hay envío ni registro. Fuente principal: [convocatoria oficial](https://www.usenix.org/conference/usenixsecurity27/call-for-papers).

## Requisitos vigentes

| Requisito | Fuente oficial | Estado del proyecto |
|---|---|---|
| Registro obligatorio con título, autores, ORCID, resumen y temas fijos: 2027-01-19 AoE | [CFP, calendario y registro](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Pendiente de decisiones de autoría y envío. |
| Paper: 2027-01-26 AoE; artefactos: 2027-01-29 AoE | [CFP, calendario](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Plazos futuros; no se enviará automáticamente. |
| PDF U.S. letter, dos columnas, 10 pt, 12 pt leading, plantilla USENIX, cuerpo máximo de 13 páginas | [CFP, formato](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | El borrador inglés compiló con pdfLaTeX y el estilo oficial intacto; PDF actual de seis páginas inspeccionado. Falta desarrollar el contenido para un envío. |
| Apéndice Open Science obligatorio; apéndice de ética recomendado | [CFP, política de ciencia abierta](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Ambos están redactados provisionalmente; el enlace anónimo del artefacto falta. |
| Revisión anónima; enlaces de artefactos sin identidad ni rastreo | [CFP, envío anónimo](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Hay una copia local sin identificadores directos con replays locales y de CI de proveedores. Falta un enlace anónimo; el repositorio público y detalles contextuales podrían identificar al autor. |
| Sin categoría de replication submission; se juzga novedad, rigor y contribución de seguridad | [CFP, alcance](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | El trabajo se plantea como método y oráculos, no como réplica. El valor incremental frente a trabajos de passkeys debe defenderse mejor. |
| IA permitida con responsabilidad humana por todo el contenido, datos, código y citas | [CFP, política de IA](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Requiere lectura y aprobación humana completa antes de un envío. |
| Si se acepta, al menos un autor debe registrarse a precio completo y presentar | [CFP, asistencia](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | La tarifa 2027 no está fijada en la convocatoria consultada; no se asume un importe. |

## Material preparado

- `submission/main.tex`: reescritura inglesa del argumento central, método, denominadores, controles exploratorios, límites, apéndice Open Science y ética. Sin nombres de autores. Este es un borrador para iterar, no un PDF de envío.
- `official_template.zip`: ZIP oficial descargado de `https://www.usenix.org/sites/default/files/usenixsecurity2027_latex_templates.zip`, SHA-256 `7dc55fc858881a7d64a06d7c8277be25c6dcc6070b17f74ef0d8a6bed70aa38e`.
- `template/usenix.sty` y `official_pdf/usenix.sty`: estilo oficial sin modificar. `submission/usenix.sty` es una copia de previsualización XeTeX. El flujo CI compiló `official_pdf/main.tex` con pdfLaTeX sin ajustes de formato prohibidos.

## Evaluación de ajuste

El tema encaja en seguridad web, protocolo y medición. El límite mayor es científico, no de maquetación: los casos externos son rutas seleccionadas y el intercambio CXP público entre dos proveedores sigue sin medirse. El borrador inglés demuestra que el argumento puede escribirse con las afirmaciones acotadas, pero hoy no justifica anunciar que el paper está listo para USENIX Security. Se necesita una comparación más profunda con trabajos previos y una decisión sobre si el aporte basta para un venue de sistemas de esta exigencia. Las revisiones independientes siguen pausadas por decisión del autor.

La siguiente versión de envío deberá (1) verificar cada cita y metadato bibliográfico, (2) incorporar la reproducción aislada y el replay auditable sin confundirlos con réplica independiente, (3) preparar artefacto anónimo y enlace estable, (4) revisar con autores responsables cada línea generada o traducida con asistencia de IA, y (5) ampliar el manuscrito antes de considerar un envío. La disponibilidad de un enlace anónimo y los ORCID dependen de decisiones del autor; no se inventan. Las revisiones independientes están pausadas por decisión del autor.

## Avance del 20 y 21 de octubre: PDF con estilo oficial

El borrador inglés ahora precisa los ocho estratos, las dos aserciones de C1, los
controles C2 y C3, el límite de los hashes PRF y el carácter interno de la
reproducción en entorno limpio. Se cotejaron los metadatos bibliográficos de
Ramat, Jannett y Büttner con sus publicaciones originales.

El [run 40327351880](https://github.com/fedequark/PasskeyTransit/actions/runs/40327351880)
compiló con pdfLaTeX y comparó byte a byte la copia de usenix.sty con la
plantilla oficial. El PDF descargado tiene cinco páginas U.S. letter, dos
columnas y fuentes Type 1 incrustadas; SHA-256:
b13476715f4d4026ba4e2b25e6a0ca8a713d48d054de68ea50a2b8ac5a179467.
Se renderizaron e inspeccionaron las cinco páginas sin detectar texto cortado
ni superpuesto. El archivo está en compiled/main.pdf.

El borrador ahora contiene tablas comprobadas automáticamente para las 12 rutas
y ocho estratos, explicación de C2/C3 y un control estructural del borrador
CXP. El cuerpo sigue siendo corto para USENIX Security: falta profundizar el
análisis metodológico y la contribución frente a trabajos previos. El PDF no
se presenta como listo para enviar.

## Artefacto anónimo provisional

anonymous_artifact/passkeytransit-anonymous-staging.zip permanece **local**.
Su auditoría y verificador recalculan 6.144 filas C1, 96 grupos, 80 filas C2,
960 secuencias y 1.920 eventos C3 desde una extracción limpia. Se quitaron
identificadores directos, rutas locales y el commit de proyecto en las filas
originales; no se incluyeron historial Git ni manifiestos de procedencia
originales. Incluye los informes públicos de Fenko, Proton y fase 14 con un
verificador que recalcula sus firmas y relaciones PRF. En esta versión inicial
no estaban los ZIP de replay; el avance del 26 de octubre incorporó un paquete
local para Fenko/Proton. Su nombre y contenido
podrían relacionarse contextualmente con el proyecto público. No hay enlace
de revisión ni publicación del ZIP.

## Avance del 21 de octubre: procedencia y comparación externa

El paquete local ahora conserva el ZIP original del replay de fase 14. Su
verificador comprueba que los dos informes incluidos son idénticos a los del
ZIP. El SHA-256 de ese ZIP coincide con el digest que GitHub Actions muestra
para el artefacto del run 39446248808. El vínculo identificador con el run
queda en un archivo local privado, fuera del paquete de revisión. Esto
fortalece la trazabilidad del control de navegador. Los replays locales de
Fenko y Proton se incorporaron el 26 de octubre; no tienen atestación de CI.
Tampoco resuelve el riesgo de identificación contextual.

La comparación con trabajos previos se amplió a abuso interpersonal,
compromiso de gestores en la nube y exportación propuesta para credenciales
ligadas al dispositivo. Se distinguió la unidad de análisis propia: cada
intento de migración controlada y sus oráculos posteriores. Un cotejo
reproducible del esquema del borrador CXP con los tipos Rust públicos de
Bitwarden detectó tres campos del borrador ausentes en esos tipos. Es una
observación del código fuente, no una ejecución de intercambio CXP. Un
ensayo criptográfico completo sigue pendiente de un perfil HPKE/JWE
interoperable y una segunda implementación ejecutable.

## Avance del 26 de octubre: parser externo y replays locales

El [run 40327351891](https://github.com/fedequark/PasskeyTransit/actions/runs/40327351891)
compiló los tipos Rust CXP públicos de Bitwarden en la revisión fijada
`32da4c8b0a4abdd0b46fae79c31e0fdb50150396`. La solicitud y la respuesta
sintéticas se interpretaron, pero una serialización posterior omitió
`archive` y `mode` de la solicitud y `archive` de la respuesta. Una versión
256, representable por el campo de 16 bits pero sin ser una versión publicada,
fue rechazada por el tipo de 8 bits. Es una limitación de amplitud futura,
no un fallo de conformidad actual. El resultado caracteriza ese parser; no
prueba intercambio entre gestores, autenticación JWE ni descifrado HPKE.

Una segunda biblioteca abierta de tipos, [`go-cxp`](https://github.com/nvinuesa/go-cxp)
en la revisión `94659f317ac62470a149cb3ecb769ed5d03d18a1`, pasó la misma
fixture en [CI 40327351875](https://github.com/fedequark/PasskeyTransit/actions/runs/40327351875).
Conservó `archive` en solicitud y respuesta, pero descartó `mode` en la
solicitud. La comparación ejecutada de dos parsers no constituye un ensayo
de transferencia entre proveedores.

Los informes descargados de ambos runs coinciden byte por byte con los
archivos conservados: SHA-256 Rust
`f7ef0dc9d857d73d58c203397362ffc7ea39a2d3fde8f39ab2aca91577dbbf2c`
y Go `481c7951fb75af86b13ea23ef369f9d8c5ce4d8f2f3c5929b2d2589d98346c10`.
El `Cargo.lock` de Rust coincide también, SHA-256
`e071af0ce194b76820c71251dbecaa050004bd6b0052be69a943fa8a071b83a5`.

Se repitieron localmente los casos sintéticos de Fenko (importación y vuelta
entre perfiles) y Proton. Un paquete local conserva los informes y los
snapshots exactos de runners, protocolos y dependencias. Desde una
extracción limpia se verificaron 40 firmas y 18 vínculos PRF de Fenko,
12 firmas y 12 relaciones PRF de Proton. El paquete no contiene bóvedas,
claves privadas ni semillas PRF; tampoco tiene atestación de ejecución
independiente o de CI. El artefacto anónimo local ahora incluye este paquete
y ambos informes de parser, y su verificador de filas volvió a pasar. Continúa
sin enlace anónimo estable y con riesgo de identificación contextual.
El ZIP de replays locales tiene SHA-256
`dceb35572eca3ebf6ccd43554a785f8e3192cac2b6d6dca34ddac9c9a000dd65`;
el ZIP anónimo local se actualizó el 26 de octubre con el perfil cifrado
descrito más abajo.
La matriz diferencial de los dos parsers se genera desde ambos informes
verificados y se vuelve a calcular al verificar el ZIP anónimo; conserva
la distinción entre campos obligatorios descartados y la limitación futura
del campo de versión. SHA-256 de la matriz:
`0dca7c4fc2874281f5c26b76c81e31b2be02ec084cb0ab205bba49aba9dda2cf`.

El [run PDF 40327351880](https://github.com/fedequark/PasskeyTransit/actions/runs/40327351880)
compiló el manuscrito revisado con la plantilla oficial. El PDF tiene cinco
páginas U.S. letter y SHA-256
`b13476715f4d4026ba4e2b25e6a0ca8a713d48d054de68ea50a2b8ac5a179467`.
Se inspeccionaron visualmente las cinco páginas. El
[run de verificación 40327351777](https://github.com/fedequark/PasskeyTransit/actions/runs/40327351777)
también pasó.

## Avance del 26 de octubre: perfil cifrado experimental

Se implementó un perfil **privado y no normativo** que envuelve con HPKE una
clave de contenido distinta para cada archivo JWE de un ZIP de dos miembros.
El exportador Python y el importador Node, escritos por este proyecto,
recuperaron el mismo CXF sintético con campos HMAC. Pasaron nueve controles
locales y cuatro controles entre runtimes; entre los negativos están alterar el
JWE, la clave envuelta, el destinatario, el archivo negociado y el estado de
replay. El [run de verificación 40332016417](https://github.com/fedequark/PasskeyTransit/actions/runs/40332016417)
pasó. Los informes tienen SHA-256
`e608f9dcee5f46f52f4cd70c72e3329337f8b6583a711e155194cf2bad811aba`
y `fea15a29a06fff6aa14d889965726b76a90d7ff4a2f8681e63112cba79b8423b`.

El artefacto anónimo local incorporó código, informe y verificador del nuevo
perfil; una extracción limpia volvió a pasar con 117 miembros verificados.
SHA-256 del ZIP: `37c8d71906dda2b23dd80977566a12836e6aa507d90aabe333bb5d60c9975cfb`.
El perfil **no** demuestra que un gestor externo acepte ese mapeo HPKE/JWE.
La auditoría de código abierto documentada en
`docs/CXP_EXTERNAL_PROVIDER_GATE.md` muestra que el parser de Bitwarden
Android inspeccionado recibe CXF JSON y delega la importación al SDK y al
servicio de cuenta; no provee un motor ZIP/JWE independiente ejecutable en
este host. Sigue faltando un intercambio con un proveedor externo completo.

La versión actual del manuscrito compiló en el
[run PDF 40332016393](https://github.com/fedequark/PasskeyTransit/actions/runs/40332016393)
con la plantilla oficial sin modificaciones. El PDF tiene cinco páginas
U.S. letter y SHA-256
`d22385cc8d7f5096bd1dea45c8cb64985e0b8dc0a525eb0d877464ea59ad9d17`.
Se inspeccionaron visualmente las cinco páginas. El
[run de verificación 40332016417](https://github.com/fedequark/PasskeyTransit/actions/runs/40332016417)
pasó. El run PDF anterior `40331486215` compiló seis páginas porque dos
referencias quedaron aisladas; se corrigió el apéndice antes de fijar
este PDF.

## Avance del 26 de octubre: interoperabilidad JOSE externa

El mapeo genérico `HPKE-3-KE` del Internet-Draft JOSE -22 se probó con
dos implementaciones: el módulo Python de este proyecto y la librería
Go independiente `jwx/v4` v4.6.0. Cada una descifró el JWE de la otra
con el mismo CXF sintético; se rechazaron ciphertext alterado y claves
de destinatario incorrectas. Pasaron cinco controles. El
[run de CI 40334103465](https://github.com/fedequark/PasskeyTransit/actions/runs/40334103465)
repitió el ensayo. El informe, que no guarda claves ni texto claro,
tiene SHA-256
`3f6de00e7d472ee15681298b07b39f7c09b80483b0be81863ca58ba43d4701da`.
Es interoperabilidad criptográfica JOSE, no un ZIP CXP importado por un
gestor externo. El borrador JOSE todavía no es un RFC publicado.

El ZIP anónimo local se regeneró y verificó desde una extracción limpia:
126 miembros con hash y cinco nuevos controles JOSE. Su SHA-256 actual
figura arriba. Sigue sin URL anónima estable y con riesgo de asociación
contextual. El [run PDF 40334103538](https://github.com/fedequark/PasskeyTransit/actions/runs/40334103538)
compiló la versión actual con la plantilla oficial. El PDF tiene cinco
páginas U.S. letter, inspeccionadas visualmente, y SHA-256
`5200a94756f7fe6fe2cdc64b3ca68261a7cca45165d517d5756c90ca0347e18f`.

## Avance del 26 de octubre: ZIP CXP con JOSE externo

Se construyó otro ZIP CXP experimental de dos miembros, ambos JWEs
`HPKE-3-KE` según el borrador JOSE -22. La librería Go independiente
`jwx/v4` descifró índice y documento; el adaptador Python del proyecto
comprobó selección de suite, archivo, identificador de exportador,
vínculo a la solicitud, índice y forma CXF. Cinco controles pasaron,
incluidos JWE alterado, destinatario incorrecto, exportador cambiado y
archivo no negociado. El [run de CI 40335331441](https://github.com/fedequark/PasskeyTransit/actions/runs/40335331441)
pasó; el [run final 40335869966](https://github.com/fedequark/PasskeyTransit/actions/runs/40335869966)
también pasó. SHA-256 del informe:
`cd0f9ba6a5afc80557b3d87239c09f7b658d72262b77b09b7dc2c272eb397561`.
El ZIP, el índice y el adaptador CXP son nuestros; el gestor externo
completo y una aserción posterior siguen `NOT_EVALUABLE`.

La extracción limpia del artefacto anónimo actual verificó 132 miembros
con hash y los cinco nuevos controles. El [run PDF 40335870754](https://github.com/fedequark/PasskeyTransit/actions/runs/40335870754)
compiló la versión actual del paper con la plantilla oficial: cinco
páginas U.S. letter inspeccionadas visualmente. SHA-256 del PDF:
`2e2c85a98a7874e0ab699fa9d6893d0a665485ff70e58530be4b51ef47fc16d0`.

## Avance del 26 de octubre: separación Android CXF / CXP

La guía oficial de Android (actualizada el 23 de octubre de 2026) describe
`ProviderEventsManager` con CXF JSON transportado por un content URI. Ese
ensayo móvil mide transferencia entre proveedores por la API de Android;
no prueba el ZIP/JWE del borrador CXP. El manuscrito ahora explicita esta
distinción y conserva el resultado móvil comunicado por el operador fuera
de los resultados medidos. `docs/CXP_EXTERNAL_PROVIDER_GATE.md` separa las
dos puertas de aceptación.

La inspección de Proton Pass common 2.0.0 encontró un módulo CXP abierto
con intercambio HPKE directo y conversión CXF. Es un candidato nuevo para
una prueba cruzada de implementación, pero su perfil no es el ZIP/JWE del
proyecto, su prueba interna no constituye interoperabilidad externa, y aún
no ejecutamos la compilación del módulo con un adaptador independiente.

El ZIP anónimo local se regeneró con la corrección del paper. Una extracción
limpia verificó 132 miembros y los controles previos; SHA-256 del ZIP:
`426ab4312ed6f1170e9c0c033ba119beb00e54e45b40e26b9938832d608c7de9`.
La recompilación y paginación finales se registran en el hito siguiente.

## Avance del 26 de octubre: CXP directo con implementación externa Proton

Se compiló Proton Pass common 2.0.0 desde el código abierto. El objeto de
etiqueta anotada `2.0.0` es `b22db5ca6fef03d0e9467c0305f9af8a2826be35`;
su commit de código es `69a0927f0fe7071243d6c38e404459a69210fdd4`.
El `Cargo.lock` fija también las dependencias. En el
[run 40340988748](https://github.com/fedequark/PasskeyTransit/actions/runs/40340988748)
pasaron cuatro controles de login sintético, ocho del camino
Proton→Python con passkey, y siete del camino Python→Proton. La passkey
recuperada conservó identificador, clave privada y ambas semillas HMAC;
cuatro firmas de software y cuatro comprobaciones PRF pasaron en la
primera dirección. La segunda importó y reexportó la passkey sin avisos,
con los mismos campos, y rechazó el ciphertext alterado. Los tres
informes verificaron localmente y tienen SHA-256, respectivamente:

- Login: `3a6866fbf6206b60aa4e81f59de9e652c0785d74b8d2e6ae3124cd47ef4fa497`.
- Passkey Proton→Python: `3b45985557c38eebbd51b7ad69941fa67424eeb34b59bf079a017b227e69a6f6`.
- Passkey Python→Proton: `853e658067f4dfc0c1aba3b6b36a6fad1420fd914903bb3f387e7548ba8cbf58`.

Proton usa un ciphertext HPKE directo con CXF JSON; el borrador CXP
requiere un ZIP con JWE por miembro. Por tanto, este hito demuestra
interoperabilidad bidireccional de ese **perfil de implementación**,
pero no conformidad al payload ZIP/JWE del borrador ni importación en
dos apps con almacenamiento persistente. Las aserciones verificadas son
de un autenticador de software y un RP local, no de un RP desplegado.

El [run general 40340988704](https://github.com/fedequark/PasskeyTransit/actions/runs/40340988704)
pasó. El [run PDF 40340990138](https://github.com/fedequark/PasskeyTransit/actions/runs/40340990138)
compiló el paper actualizado con la plantilla oficial: cinco páginas
U.S. letter. Se inspeccionaron las páginas finales tras el cambio;
SHA-256 del PDF: `cd949aae0eee68d4d0fdd4b61a7121d4c1d86047aecb75f4b5d9d955ccc3cebfd`.
El ZIP anónimo **local** se reconstruyó y verificó desde una extracción
limpia con 143 miembros con hash. SHA-256:
`c76ef792a50a849b64176d94fb428ff2ce7354b4d403c3f82b96546b3c78208d`.
Sigue sin URL anónima estable ni revisión independiente, que permanece
pausada por el autor.

## Avance del 26 de octubre: replays de proveedores en CI limpio

El [run 40344602464](https://github.com/fedequark/PasskeyTransit/actions/runs/40344602464)
pasó en Ubuntu 24.04 con el commit de proyecto
`dfbeee710445d140ad7b1ad462baf26aa359b4e0`. El job Fenko compiló la
extensión desde la revisión fijada `2d873fbe25257250de6e322e9d785b97b17a544f`,
ejecutó su prueba CXF y sus chequeos de tipos, e hizo importación y vuelta
entre perfiles en Chromium. El job Proton instaló el paquete 2.0.0 con
dependencias fijadas y repitió el control de software CXF/PRF.

Se conservaron los ZIP originales de ambos jobs y los tres informes extraídos.
Los SHA-256 de los ZIP coinciden con los digests de GitHub: Fenko
`b9004d22569304d68424166ffba6c96ad8b57a96cfe1995cfc5e4973d88593e7`
y Proton `f68347ec426bbf402a47ab2dfb6695c2f81bd3e3364fb12efe9861123b545fd7`.
`tools/verify_provider_ci_replay.py` verificó la igualdad byte a byte de
los tres informes y recalculó 40 firmas y 18 vínculos PRF de Fenko,
12 firmas y 12 relaciones PRF de Proton.

El ZIP anónimo **local** incorporó ambos ZIP originales y los informes,
dejando el vínculo identificador con GitHub en un sidecar externo. Una
extracción limpia verificó 146 miembros con hash y repitió esos chequeos;
SHA-256 del ZIP: `9fa07f23c72eb97261fb27063a06a6389e5c71a0032d9f82ef81671489cc2035`.
El job de Chrome del runner falló porque no cargó la extensión; el resultado
que se conserva utiliza el Chromium incluido por Playwright. El run anterior
con instalación del navegador sin progreso se canceló para evitar cómputo
innecesario. CI demuestra repetición automatizada por el mismo equipo en otro
entorno, no réplica independiente ni CXP entre dos apps de proveedores.
Los ZIP originales de Phase 14 y del replay local se añadieron al repositorio
con sus informes; el constructor del paquete usa solo archivos bajo control
de versiones y normaliza los textos ordinarios a LF. Los dos informes de
Phase 14 conservan sus bytes originales. Así, un checkout limpio produce
el mismo ZIP de revisión pese a los archivos de trabajo no registrados.

El [run PDF 40347388639](https://github.com/fedequark/PasskeyTransit/actions/runs/40347388639)
compiló la versión condensada con el estilo oficial sin modificar. El PDF
tiene cinco páginas U.S. letter; se inspeccionó la última para descartar una
referencia huérfana. SHA-256:
`a6e5254613d87550492c5c22f938b5a3ad7e5907e31e9a8c1534bb8c2c2c61ff`.

El [run de reproducción 40348206066](https://github.com/fedequark/PasskeyTransit/actions/runs/40348206066)
reconstruyó el paquete anónimo local en Ubuntu 24.04 y obtuvo el mismo
SHA-256 `9fa07f23c72eb97261fb27063a06a6389e5c71a0032d9f82ef81671489cc2035`
que Windows. El verificador extraído pasó con 146 miembros, igualdad de
los tres informes con los ZIP originales y 52 firmas y 30 vínculos PRF de
proveedores. El workflow es manual para evitar runs repetidos y no publica
un artefacto que pudiera confundirse con un enlace anónimo de revisión.

## Avance del 26 de octubre: exportador CXP abierto

El [run 40350620050](https://github.com/fedequark/PasskeyTransit/actions/runs/40350620050)
compiló `cxporter` en la revisión `96bab31fdadcfd295542bba86b8ec8bd2355294a`,
ejecutó sus pruebas internas y exportó dos passkeys CXF sintéticas a un ZIP
con índice y documento JWE. Un importador Python del proyecto descifró ambos
miembros, comprobó la conservación de identidad, clave, user handle y estado
HMAC, y rechazó receptor erróneo y ciphertext alterado. El control de
software Proton produjo ocho firmas y ocho resultados PRF verificados de
nuevo desde los datos públicos. El ZIP original del run tiene SHA-256
`e880f5a48b530caff22e7149e6b436d2a1c0451de5ca0d86a0e7c1898454cd09`.

La respuesta de `cxporter` omite `archive`, campo exigido por el borrador;
su `alg` JWE difiere del control JOSE `HPKE-3-KE`. El ensayo mide un exportador
externo abierto con importador propio, sin segunda app proveedora ni almacén
persistente. El reporte conserva firmas y hashes públicos, pero el descifrado
del ZIP requiere repetir el run. La reproducción en CI es del mismo equipo.
El paquete anónimo local actualizado tiene 152 miembros con hash y SHA-256
`f09558cfe6e9cca45debd8e31b3cda792e2600f9dd7f0f85b22cb7c86921c090`;
su verificador pasó en una extracción limpia de Windows.

El [run PDF 40352354965](https://github.com/fedequark/PasskeyTransit/actions/runs/40352354965)
compiló el manuscrito actualizado con el estilo oficial. Tiene cinco
páginas U.S. letter; la última se inspeccionó visualmente y las 19
referencias terminan allí. SHA-256 del PDF:
`0a116c8c319e59d79021c247a1f4499d4b3a6da3d9ff53b0443d60ce786ee8fb`.

## Avance del 26 de octubre: cruce entre dos implementaciones abiertas

En el [run 40353576594](https://github.com/fedequark/PasskeyTransit/actions/runs/40353576594),
un segundo importador experimental (`cxp_poc2`, revisión
`fee19d9ac392ffe0153bea8b917aa0a66f12b272`) abrió primero su propio
ZIP y conservó el estado de una passkey sintética. Al recibir luego el ZIP
de `cxporter` para su propia clave de destinatario, rechazó en dos repeticiones
el `alg` del primer JWE. No llegó a reconstruir CXF ni a una aserción RP.
El parser de la respuesta completa también rechazó antes la ausencia de
`archive`; el ensayo del JWE pasó por alto solo ese parser para aislar el
segundo fallo.
El rechazo demuestra incompatibilidad entre esos dos perfiles de código;
no demuestra cuál satisface el borrador ni mide dos apps instaladas.
El ZIP original del informe CI tiene SHA-256
`cd1d9abc381e2e2ea0d1b4387da1d64c2d24eb11e4e09696438d95b9b2ada9c3`.

El [run ampliado 40354422120](https://github.com/fedequark/PasskeyTransit/actions/runs/40354422120)
repitió el rechazo del parser por ausencia de `archive` y, al aislar el
payload, el rechazo del `alg` JWE. El ZIP original de ese informe tiene
SHA-256 `1536898b57077d6a5902750d36baf4768512c29cecdd606b1fc937a0c227cab7`;
éste es el que integra el paquete anónimo local.

El [run PDF 40354661711](https://github.com/fedequark/PasskeyTransit/actions/runs/40354661711)
compiló el manuscrito con los dos controles negativos en cinco páginas
U.S. letter. Se inspeccionó visualmente la última: las veinte referencias
quedan completas en la página cinco. SHA-256 del PDF:
`6d4a6cdcbcd841971a165a49da24a1aab2f8a03975d2d39694be2d45e4e4b5ef`.
El paquete anónimo de ese hito contenía 158 archivos con hash, pasó tras
extracción limpia en Windows y tiene SHA-256
`7ca49ca3324d3ce0e1594927f1acd8fad58a01618034c0f56726f5f98f5840ad`.
El [run de reproducción 40355053855](https://github.com/fedequark/PasskeyTransit/actions/runs/40355053855)
obtuvo exactamente ese hash en Ubuntu 24.04. La extracción verificó los
158 miembros, el ZIP original del segundo importador y los dos rechazos
registrados. Es una repetición automatizada del mismo equipo.

El [run 40355464186](https://github.com/fedequark/PasskeyTransit/actions/runs/40355464186)
añadió un control del índice descifrado: en ambas repeticiones carece del
objeto `{header, documents}` que espera el segundo importador. Como éste
rechaza antes por esquema y JWE, se clasifica como diferencia de forma
inferida de fuente y plaintext, no como un tercer fallo de importación
observado. El nuevo ZIP original del informe tiene SHA-256
`09255d0f0f29ce913de06c05f98981efc574d66f2c3d094662a4ad23edd43b65`.
El paquete anónimo local actualizado conserva 158 archivos con hash y tiene
SHA-256 `3017684d625a12c816b969bde931eb07c69ee4968f79303db67b3dcb4a1e13b6`;
pasó la extracción y verificación local en Windows.
El [run 40355870182](https://github.com/fedequark/PasskeyTransit/actions/runs/40355870182)
reconstruyó en Ubuntu exactamente el mismo SHA-256 y verificó los 158
miembros, ocho firmas del informe `cxporter` y los dos rechazos del cruce.

## Avance del 26 de octubre: estimando y validez del manuscrito

La versión actual distingue el estimando C1 definido sobre rutas importadas
con aserción, el oráculo `largeBlob` y los distintos niveles de evidencia.
Corrige una frase previa: los 512 casos C1 de falsa tranquilidad fallaron
en `largeBlob`; el oráculo UV no falló en esa campaña. Agrega una comparación
de los caminos ejecutados y amenazas a la validez de construcción, interna,
externa y reproducibilidad. Los resultados de campañas anteriores que
motivaron cambios del protocolo no se presentan como confirmación nueva.

El [run PDF 40356857613](https://github.com/fedequark/PasskeyTransit/actions/runs/40356857613)
compiló ambas fuentes actualizadas con el estilo oficial. El PDF actual
`compiled/main.pdf` tiene seis páginas U.S. letter; se inspeccionaron las
páginas cinco y seis, con las veinte referencias completas. SHA-256:
`2f4f3ca09bb11e0446a93313f587b43f19aa09d7269bca03826d197e8e9cdc3a`.
El paquete anónimo local se reconstruyó a partir de esta fuente: 158 miembros
con hash, extracción y verificación `PASS` en Windows, SHA-256
`a30d664dc922a97f45136e555a7803113842f81b26387646374f44899b0e219e`.
El [run 40357387301](https://github.com/fedequark/PasskeyTransit/actions/runs/40357387301)
reconstruyó exactamente ese SHA-256 en Ubuntu 24.04 y verificó el paquete
extraído. `claim_trace.md` enlaza las cifras y los casos ejecutados del
manuscrito con los datos y verificadores retenidos.

## Avance del 26 de octubre: vector público de ciphertext CXP

Se conserva una respuesta ZIP/JWE real del exportador abierto `cxporter`
para una passkey **sintética**, junto con el CXF esperado y la derivación
de una clave receptora de prueba pública. El ZIP tiene dos archivos JWE y
SHA-256 `60927b038c4d324f0650541475f7b642b6af5bbce3da22501bddfe1bc80a8dd0`.
El verificador estático comprobó bytes, estructura y algoritmo; el adaptador
ejecutó el parser y `openPayload` de `cxp_poc2` en su revisión fijada. En la
respuesta íntegra faltó `archive`; al añadir sólo ese campo pasó el parser
y falló después por `alg` JWE, antes de recuperar CXF. El
[run 40359254321](https://github.com/fedequark/PasskeyTransit/actions/runs/40359254321)
repitió ese vector y produjo uno fresco con los mismos dos resultados.
Sus dos informes JSON están conservados. El digest del artefacto CI original
es `sha256:e079dfbe0ede2104e2e8fa161f0b4c11999bf6c5f9f8b4ed1b9a30d9ba4fb018`.
Esto mide incompatibilidad entre perfiles de dos implementaciones de
investigación, sin transferencia exitosa entre apps proveedoras ni juicio
normativo de conformidad.

El [run PDF 40359254305](https://github.com/fedequark/PasskeyTransit/actions/runs/40359254305)
compiló la explicación del vector con el estilo oficial: seis páginas
U.S. letter, quinta y sexta páginas inspeccionadas, veinte referencias
completas. SHA-256 de `compiled/main.pdf`:
`50c81a9824f51459f8924ba849ac244b7689e6797fbb36948498e20ff783f2f8`.
El paquete anónimo local contiene el vector, adaptadores, verificadores e
informes CI; tiene 165 miembros con hash, pasó extracción y verificación
local en Windows y tiene SHA-256
`e629d46e6e36b18f9ec70847731f8e7f41ed4d7d6322813fed74a287fdfcd34a`.
El [run 40360147948](https://github.com/fedequark/PasskeyTransit/actions/runs/40360147948)
reconstruyó exactamente ese SHA-256 en Ubuntu 24.04 y verificó el paquete
extraído. Es una repetición automatizada del mismo equipo.

## Avance del 26 de octubre: aislamiento del formato del índice

El índice del vector CXP sintético se descifró con una clave receptora de
prueba pública; su plaintext tiene SHA-256
`e8f16dc16ad36a18f75b279c1bc7f5066ef13edcb43f6990f407cfc75f1dcd7c`.
Un control transformado hizo primero una autoimportación positiva con
`cxp_poc2`, reemplazó sólo el índice por ese plaintext dentro del perfil
JWE del propio importador y ejecutó su `openPayload` sin modificar. El
resultado fue `CxpPayloadError: index.jwe is not {header, documents}` tanto
localmente como en el [run 40361395703](https://github.com/fedequark/PasskeyTransit/actions/runs/40361395703).
El digest del artefacto CI original es
`sha256:e61ab4e12dc8e5f5073aadbb64382239aada81b285273888e44938a179ae6ce7`.
El ZIP transformado no es la exportación original de `cxporter`: el ensayo
ubica una diferencia de formato posterior a los rechazos de esquema y
algoritmo, sin demostrar un tercer rechazo de ese ciphertext ni conformidad
normativa.

El [run PDF 40361395891](https://github.com/fedequark/PasskeyTransit/actions/runs/40361395891)
compiló esta distinción en seis páginas U.S. letter. Se inspeccionaron las
páginas cinco y seis y las veinte referencias quedan completas; SHA-256 del
PDF actual `compiled/main.pdf`:
`e9dbb40755662f61a8e539bb67c46ead13d1e94253e5bce3b14ebd487b0dc40d`.
El paquete anónimo local actualizado conserva ambos informes del control
de índice: 172 miembros con hash, extracción y `verify.py` aprobados en
Windows, SHA-256
`0dd2378ef508b0c4387d950db21e7882bfc87e654218f36a6c22257d060307cc`.
El [run 40362009612](https://github.com/fedequark/PasskeyTransit/actions/runs/40362009612)
reconstruyó exactamente ese hash en Ubuntu 24.04 y verificó el paquete
extraído. Sigue siendo reproducción automatizada del mismo equipo.

## Avance del 26 de octubre: control positivo de importación hasta RP

El PoC `cxp_poc2` fijado en `fee19d9` completó cuatro trayectos con
credenciales sintéticas: transferencia directa e indirecta bajo políticas
`spec-minimal` y `hardened`. En cada trayecto su RP local verificó el
registro, el acceso con Provider A antes de importar, el acceso con Provider B
después de importar y un nuevo acceso con A. B importó una passkey y el RP
conservó un solo ID de credencial. El informe local y el del
[run 40363074055](https://github.com/fedequark/PasskeyTransit/actions/runs/40363074055)
son byte a byte iguales (SHA-256
`abbf5fc26fda44ae6cf5ed6c32bfd4e838a4a730e54c02ec1d4bb5b79df93b90`).
Este control demuestra la capacidad interna del importador experimental para
usar la credencial ante un RP de software. No procesa el ciphertext original
de `cxporter` ni constituye migración entre aplicaciones proveedoras.

El manuscrito incorpora esa distinción. El paquete anónimo actualizado
(177 miembros con hash, SHA-256
`5d8a492aa626fe19cf586ab1dc1b8a9611cdc053b982af616b551e28fb0f0c18`)
conserva ambos reportes y el probe. Su `verify.py` pasó sobre una extracción
en Windows y el [run 40363849463](https://github.com/fedequark/PasskeyTransit/actions/runs/40363849463)
reprodujo el mismo ZIP en Ubuntu.

El [run PDF 40363849442](https://github.com/fedequark/PasskeyTransit/actions/runs/40363849442)
compiló el manuscrito actualizado en seis páginas U.S. letter. Las páginas
cinco y seis se inspeccionaron después de la descarga; el PDF en
`compiled/main.pdf` tiene SHA-256
`06af9a76ef7ab5f207efa64cb0e38f74e22c22a78231aac3e60739dc95b76d78`.

## Avance del 26 de octubre: ciphertext externo hasta RP con adaptador

Se registró una passkey sintética en el RP local de `cxp_poc2`, se exportó
su CXF con `cxporter` y se descifró el ZIP/JWE original mediante código
Python del proyecto. Un adaptador insertó directamente la credencial
recuperada en el almacén B del PoC; el mismo RP verificó una firma de B con
el ID registrado originalmente. Pasó en dos ejecuciones locales y dos del
[run 40364915962](https://github.com/fedequark/PasskeyTransit/actions/runs/40364915962).
Los reportes conservados contienen hashes del ZIP y resultados públicos;
no contienen claves privadas. El importador CXP propio de `cxp_poc2` no
participa en esta ruta y mantiene su rechazo del mensaje original. Por eso
el resultado prueba usabilidad del material CXF recuperado mediante un
adaptador explícito, no interoperabilidad CXP entre proveedores.

El paquete anónimo vigente contiene los informes local y CI del adaptador:
183 miembros con hash y SHA-256
`7741927f50a733f8d0b9e4ac80ca93216b88029300634b79bd5f0713cc69104d`.
Pasó verificación tras extracción en Windows y la reproducción idéntica en
[Ubuntu run 40366050590](https://github.com/fedequark/PasskeyTransit/actions/runs/40366050590).
El [PDF run 40366050767](https://github.com/fedequark/PasskeyTransit/actions/runs/40366050767)
compiló el texto final en seis páginas U.S. letter; inspeccioné las páginas
cinco y seis. SHA-256 de `compiled/main.pdf`:
`8b76cd698610f7d10a350bd1f6e814b0f06dff25b20723c39f4c10a603640bb5`.

## Avance del 26 de octubre: auditoría Android CXF abierta

Se fijaron revisiones de Keyguard y Monica y se cotejaron sus rutas de
importación de passkeys con tres XML originales de sus propios CI: 62 pruebas
sin fallos. El código de Keyguard omite `fido2Extensions` en su modelo y
mapeos de importación y exportación; la pérdida de semilla PRF es una
**inferencia de código**, no un ensayo de transferencia. Monica rechaza
explícitamente una passkey CXF con `hmacCredentials` no nulo, y una prueba
unitaria upstream comprueba esa decisión. El
[run de auditoría 40368217675](https://github.com/fedequark/PasskeyTransit/actions/runs/40368217675)
repitió la comprobación de fuentes fijadas y de los XML en Ubuntu.

El artefacto anónimo local incluye el informe, las tres suites XML y sus
verificadores: 190 miembros con hash, SHA-256
`d94265699463d2f19be15de167a14cf1b5e5f58dbfef8476214d93b5136678a9`.
Pasó verificación tras extracción en Windows y reproducción idéntica en
[Ubuntu run 40368662799](https://github.com/fedequark/PasskeyTransit/actions/runs/40368662799).
No hay transferencia Keyguard–Monica ni aserción RP posterior a ella. Por
ello, esta auditoría no cambia el estado `NOT_EVALUABLE` de interoperabilidad
entre proveedores en la matriz de claims.
