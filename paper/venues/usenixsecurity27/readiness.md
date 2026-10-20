# USENIX Security 2027 ciclo 2: adecuación del manuscrito

Fecha de consulta: 2026-10-20. Venue de referencia para preparar un borrador en inglés; no hay envío ni registro. Fuente principal: [convocatoria oficial](https://www.usenix.org/conference/usenixsecurity27/call-for-papers).

## Requisitos vigentes

| Requisito | Fuente oficial | Estado del proyecto |
|---|---|---|
| Registro obligatorio con título, autores, ORCID, resumen y temas fijos: 2027-01-19 AoE | [CFP, calendario y registro](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Pendiente de decisiones de autoría y envío. |
| Paper: 2027-01-26 AoE; artefactos: 2027-01-29 AoE | [CFP, calendario](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Plazos futuros; no se enviará automáticamente. |
| PDF U.S. letter, dos columnas, 10 pt, 12 pt leading, plantilla USENIX, cuerpo máximo de 13 páginas | [CFP, formato](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | El borrador inglés compiló con pdfLaTeX y el estilo oficial intacto; PDF de cuatro páginas inspeccionado. Falta desarrollar el contenido para un envío. |
| Apéndice Open Science obligatorio; apéndice de ética recomendado | [CFP, política de ciencia abierta](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Ambos están redactados provisionalmente; el enlace anónimo del artefacto falta. |
| Revisión anónima; enlaces de artefactos sin identidad ni rastreo | [CFP, envío anónimo](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | El repositorio y los informes de GitHub actuales identifican al autor. Se necesita preparar una copia anónima y auditar sus metadatos antes de enviar. |
| Sin categoría de replication submission; se juzga novedad, rigor y contribución de seguridad | [CFP, alcance](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | El trabajo se plantea como método y oráculos, no como réplica. El valor incremental frente a trabajos de passkeys debe defenderse mejor. |
| IA permitida con responsabilidad humana por todo el contenido, datos, código y citas | [CFP, política de IA](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | Requiere lectura y aprobación humana completa antes de un envío. |
| Si se acepta, al menos un autor debe registrarse a precio completo y presentar | [CFP, asistencia](https://www.usenix.org/conference/usenixsecurity27/call-for-papers) | La tarifa 2027 no está fijada en la convocatoria consultada; no se asume un importe. |

## Material preparado

- `submission/main.tex`: reescritura inglesa del argumento central, método, denominadores, controles exploratorios, límites, apéndice Open Science y ética. Sin nombres de autores. Este es un borrador para iterar, no un PDF de envío.
- `official_template.zip`: ZIP oficial descargado de `https://www.usenix.org/sites/default/files/usenixsecurity2027_latex_templates.zip`, SHA-256 `7dc55fc858881a7d64a06d7c8277be25c6dcc6070b17f74ef0d8a6bed70aa38e`.
- `template/usenix.sty`: estilo original sin modificar. `submission/usenix.sty` es una copia de previsualización: desactiva `breakurl` por incompatibilidad con el compilador XeTeX integrado; `main.tex` desactiva dos funciones microtype no compatibles en ese motor. Antes de enviar se debe volver al estilo oficial y compilar con pdfLaTeX, sin ajustes de formato prohibidos.

## Evaluación de ajuste

El tema encaja en seguridad web, protocolo y medición. El límite mayor es científico, no de maquetación: los casos externos son rutas seleccionadas y el intercambio CXP público entre dos proveedores sigue sin medirse. El borrador inglés demuestra que el argumento puede escribirse con las afirmaciones acotadas, pero hoy no justifica anunciar que el paper está listo para USENIX Security. Se necesita una comparación más profunda con trabajos previos, una revisión metodológica externa y una decisión sobre si el aporte basta para un venue de sistemas de esta exigencia.

La siguiente versión de envío deberá (1) verificar cada cita y metadato bibliográfico, (2) incorporar la reproducción aislada y el replay auditable sin confundirlos con réplica independiente, (3) preparar artefacto anónimo y enlace estable, (4) revisar con autores responsables cada línea generada o traducida con asistencia de IA, y (5) ampliar el manuscrito antes de considerar un envío. La disponibilidad de un enlace anónimo y los ORCID dependen de decisiones del autor; no se inventan. Las revisiones independientes están pausadas por decisión del autor.

## Avance del 20 de octubre: PDF con estilo oficial

El borrador inglés ahora precisa los ocho estratos, las dos aserciones de C1, los
controles C2 y C3, el límite de los hashes PRF y el carácter interno de la
reproducción en entorno limpio. Se cotejaron los metadatos bibliográficos de
Ramat, Jannett y Büttner con sus publicaciones originales.

El [run 39451048105](https://github.com/fedequark/PasskeyTransit/actions/runs/39451048105)
compiló con pdfLaTeX y comparó byte a byte la copia de usenix.sty con la
plantilla oficial. El PDF descargado tiene cuatro páginas U.S. letter, dos
columnas y fuentes Type 1 incrustadas; SHA-256:
76fdecaf2e92a73e7a13cb030c823024f540c8708aad5438ab035a882450b4d1.
Se renderizaron e inspeccionaron las cuatro páginas sin detectar texto cortado
ni superpuesto. El archivo está en compiled/main.pdf.

El cuerpo del borrador ocupa aproximadamente tres páginas. Aunque cumple el
formato, sigue siendo un resumen corto para USENIX Security: falta desarrollar
análisis por ruta y estrato, método, amenazas y discusión de trabajos previos.
El PDF no se presenta como listo para enviar.
