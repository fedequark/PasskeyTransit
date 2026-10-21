# USENIX Security 2027 ciclo 2: adecuación del manuscrito

Fecha de consulta: 2026-10-20. Venue de referencia para preparar un borrador en inglés; no hay envío ni registro. Fuente principal: [convocatoria oficial](https://www.usenix.org/conference/usenixsecurity27/call-for-papers).

## Requisitos vigentes

| Requisito | Fuente oficial | Estado del proyecto |
|---|---|---|
| Registro obligatorio con título, autores, ORCID, resumen y temas fijos: 2027-01-19 AoE | [CFP, calendario y registro](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Pendiente de decisiones de autoría y envío. |
| Paper: 2027-01-26 AoE; artefactos: 2027-01-29 AoE | [CFP, calendario](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Plazos futuros; no se enviará automáticamente. |
| PDF U.S. letter, dos columnas, 10 pt, 12 pt leading, plantilla USENIX, cuerpo máximo de 13 páginas | [CFP, formato](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | El borrador inglés compiló con pdfLaTeX y el estilo oficial intacto; PDF de cinco páginas inspeccionado. Falta desarrollar el contenido para un envío. |
| Apéndice Open Science obligatorio; apéndice de ética recomendado | [CFP, política de ciencia abierta](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Ambos están redactados provisionalmente; el enlace anónimo del artefacto falta. |
| Revisión anónima; enlaces de artefactos sin identidad ni rastreo | [CFP, envío anónimo](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Hay una copia local sin identificadores directos, pero omite replays de proveedores. Falta un paquete completo y un enlace anónimo; el repositorio público identifica al autor. |
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

El [run 39607446937](https://github.com/fedequark/PasskeyTransit/actions/runs/39607446937)
compiló con pdfLaTeX y comparó byte a byte la copia de usenix.sty con la
plantilla oficial. El PDF descargado tiene cinco páginas U.S. letter, dos
columnas y fuentes Type 1 incrustadas; SHA-256:
14c67ca3c4daef0b72b8036e74b50d7a22304981e948697aaf3b35ae9c894a6c.
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
verificador que recalcula sus firmas y relaciones PRF. No contiene los ZIP de
replay ni la procedencia original necesaria para atribuir esos informes a sus
proveedores; por ello aún no respalda íntegramente el manuscrito. Su nombre y contenido
podrían relacionarse contextualmente con el proyecto público. No hay enlace
de revisión ni publicación del ZIP.

## Avance del 21 de octubre: procedencia y comparación externa

El paquete local ahora conserva el ZIP original del replay de fase 14. Su
verificador comprueba que los dos informes incluidos son idénticos a los del
ZIP. El SHA-256 de ese ZIP coincide con el digest que GitHub Actions muestra
para el artefacto del run 39446248808. El vínculo identificador con el run
queda en un archivo local privado, fuera del paquete de revisión. Esto
fortalece la trazabilidad del control de navegador, pero los ensayos de
Fenko y Proton aún carecen de archivos de replay equivalentes dentro del
paquete. Tampoco resuelve el riesgo de identificación contextual.

La comparación con trabajos previos se amplió a abuso interpersonal,
compromiso de gestores en la nube y exportación propuesta para credenciales
ligadas al dispositivo. Se distinguió la unidad de análisis propia: cada
intento de migración controlada y sus oráculos posteriores. Un cotejo
reproducible del esquema del borrador CXP con los tipos Rust públicos de
Bitwarden detectó tres campos del borrador ausentes en esos tipos. Es una
observación del código fuente, no una ejecución de intercambio CXP. Un
ensayo criptográfico completo sigue pendiente de un perfil HPKE/JWE
interoperable y una segunda implementación ejecutable.
