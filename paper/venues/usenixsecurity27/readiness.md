# USENIX Security 2027 ciclo 2: adecuación del manuscrito

Fecha de consulta: 2026-10-20. Venue de referencia para preparar un borrador en inglés; no hay envío ni registro. Fuente principal: [convocatoria oficial](https://www.usenix.org/conference/usenixsecurity27/call-for-papers).

## Requisitos vigentes

| Requisito | Fuente oficial | Estado del proyecto |
|---|---|---|
| Registro obligatorio con título, autores, ORCID, resumen y temas fijos: 2027-01-19 AoE | [CFP, calendario y registro](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Pendiente de decisiones de autoría y envío. |
| Paper: 2027-01-26 AoE; artefactos: 2027-01-29 AoE | [CFP, calendario](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Plazos futuros; no se enviará automáticamente. |
| PDF U.S. letter, dos columnas, 10 pt, 12 pt leading, plantilla USENIX, cuerpo máximo de 13 páginas | [CFP, formato](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | El borrador inglés compiló con pdfLaTeX y el estilo oficial intacto; PDF de cinco páginas inspeccionado. Falta desarrollar el contenido para un envío. |
| Apéndice Open Science obligatorio; apéndice de ética recomendado | [CFP, política de ciencia abierta](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Ambos están redactados provisionalmente; el enlace anónimo del artefacto falta. |
| Revisión anónima; enlaces de artefactos sin identidad ni rastreo | [CFP, envío anónimo](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Hay una copia local sin identificadores directos con replays locales de proveedores. Falta un enlace anónimo; el repositorio público y detalles contextuales podrían identificar al autor. |
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
El PDF final debe recompilarse para verificar de nuevo la paginación.
