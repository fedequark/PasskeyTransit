# Informe de revisión por pares y remediación

## Dictamen

**Recomendación operativa: SUBMIT AFTER MINOR REVISION.** La revisión técnica que motivó la revisión mayor quedó resuelta en PasskeyTransit v0.3.0. Lo pendiente es administrativo y específico del venue: autores y afiliaciones, declaraciones de conflicto, formularios de ética/disponibilidad, depósito con DOI y comprobación final de formato.

## Alcance revisado

Se revisaron conjuntamente el manuscrito, el código, el protocolo experimental, los datos derivados, los manifiestos de procedencia y el paquete de replicación. La revisión trazó las afirmaciones principales hasta evidencia ejecutable y distinguió controles sintéticos, interoperabilidad independiente y límites no evaluables.

Línea base de evidencia: commit `f0391e95fb8f1ac1881a1db3b377cdbf3774e161`, árbol rastreado limpio, protocolo `passkeytransit-semantic-preservation-v1.1`.

## Hallazgos anteriores y resolución

| Severidad | Hallazgo | Resolución en v0.3.0 | Estado |
|---|---|---|---|
| Crítico | La unidad experimental y el número de celdas no coincidían con los 6.144 intentos. | Se fijaron 3.072 celdas credencial×ruta, dos ejecuciones por celda y 96 grupos ruta×estrato de 64 ejecuciones. | Cerrado |
| Crítico | El perfil `strict` aceptaba alteraciones de RP-ID o discordancias de clave incompatibles con sus requisitos. | El protocolo v1.1 rechaza esos documentos antes de la ceremonia; C2 confirma el rechazo. | Cerrado |
| Alto | La procedencia podía marcar una ejecución limpia como sucia por archivos no rastreados ajenos al experimento. | Todos los recolectores miden únicamente diferencias rastreadas, staged o unstaged. | Cerrado |
| Alto | El resultado WebAuthn dependía de un booleano del mismo proceso y no conservaba un transcript verificable. | Cada importación conserva transcript público, compromiso, desafío, origen, RP-ID hash, flags, firma, contador, credential ID y user handle; el auditor independiente verifica 5.200 importaciones y 1.040 rechazos de calibración+C1. | Cerrado |
| Alto | Las inferencias y los intervalos podían leerse como estimación poblacional. | El manuscrito los rotula como sensibilidad descriptiva por bootstrap de credencial y niega prevalencia o generalización a productos. | Cerrado |
| Alto | La frontera entre HPKE base, CXP y el ensayo PQC no era suficientemente explícita. | Se separaron interoperabilidad HPKE base, extensión AAD experimental y ensayo ML-KEM-768+X25519 fuera del perfil CXP. | Cerrado |
| Medio | Faltaba una frontera de implementación externa suficientemente clara. | Se añadieron intercambio HPKE bidireccional con `cryptography`, consumidor CXF Node.js y round-trip Rust con `credential-exchange-format` 0.4.0 fijado a commit. | Cerrado |
| Medio | La versión publicada podía sobrescribir artefactos v0.2. | v0.3.0 usa nombres, resultados y release propios; los artefactos v0.2 permanecen preservados. | Cerrado |
| Medio | Referencias y límites de afirmación necesitaban actualización. | Se fijó el baseline WebAuthn 2026, se actualizaron referencias y se añadió una matriz explícita de capacidades de oráculo. | Cerrado |

## Resultados verificados

- C1: 6.144 intentos sobre 256 credenciales sintéticas, 12 rutas y dos repeticiones; 5.120 importaciones y 1.024 rechazos previos a ceremonia.
- Preservación semántica completa observable: 2.304/6.144 (37,50%).
- Degradación silenciosa entre importaciones: 1.344/5.120 (26,25%).
- Falsa tranquilidad —login correcto con otra propiedad aplicable fallida—: 2.048/5.120 (40,00%).
- C2: 80 mutaciones; 64 rechazos estructurales o de preservación estricta y 16 importaciones deliberadamente no evaluables para compatibilidad futura.
- C3: 960 secuencias; 832 rollbacks atómicos y 128 controles positivos deliberadamente no atómicos/no idempotentes.
- Interoperabilidad independiente: HPKE en ambas direcciones, consumidor Node.js, round-trip Rust y ensayo criptográfico híbrido exploratorio pasaron sus comprobaciones aplicables.
- Release: 110 entradas, 9.213 registros JSON auditados, sin campos sensibles detectados; hash del ZIP y hashes internos verificados.

## Límites residuales

Los perfiles de destino son controles de referencia, no productos comerciales. CDP no permite inyectar semillas HMAC/PRF ni `credBlob`, por lo que la preservación positiva de esas propiedades sigue siendo `NOT_EVALUABLE`. Secure Payment Confirmation no fue ejecutado. El ensayo híbrido demuestra disponibilidad criptográfica local, no interoperabilidad CXP-PQC ni seguridad de un perfil estandarizado. Estas limitaciones están reflejadas en el manuscrito y no bloquean una publicación metodológica o de artefacto, pero sí impiden afirmaciones comparativas sobre proveedores reales.

## Reproducibilidad y presentación

Los 60 tests automatizados pasan. El análisis deriva tablas y manuscrito desde resúmenes con hashes; el manifiesto incluye hashes del DOCX y PDF. El paquete `passkeytransit-v0.3.0-replication.zip` fue reconstruido y verificado con resultado `verified: true`. Se inspeccionaron visualmente todas las páginas del DOCX renderizado por Microsoft Word y del PDF renderizado por Poppler; no se observaron cortes, solapamientos ni tablas desbordadas.

## Acción previa al envío

Completar los cuatro ítems abiertos de `paper/current/SUBMISSION_CHECKLIST.md`. Si el venue exige afirmaciones empíricas sobre proveedores, ejecutar adaptadores identificados e independientes antes de ampliar el alcance del texto; de lo contrario, conservar la formulación metodológica actual.
