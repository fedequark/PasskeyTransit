# Revisión completa de PasskeyTransit v0.7.1

## 1 Veredicto ejecutivo

**Veredicto: Weak Accept. Confianza: 4/5.**

La contribución defendible es un método reproducible para medir preservación
semántica de passkeys mediante controles CXF, CXP/HPKE y WebAuthn sintéticos. Su
mayor fortaleza es la trazabilidad: el release verifica dos firmas por
importación, recalcula resúmenes desde los JSONL y regenera resultados, tablas y
manuscrito. Su debilidad dominante es externa, no interna: las proporciones
describen políticas de control deliberadamente diseñadas y no estiman productos,
proveedores ni prevalencia real. El manuscrito ahora lo dice con precisión.

No quedan hallazgos P0, P1 ni P2. Antes del envío faltan ajustes menores de
bibliografía/estado normativo y los datos administrativos del venue. La evidencia
que más aumentaría el valor científico sería ejecutar los mismos oráculos contra
un adaptador de proveedor o una segunda implementación CXP independiente; no es
necesaria para sostener las afirmaciones actuales, pero sí para generalizarlas.

## 2 Hallazgos críticos

| ID | Severidad | Ubicación | Problema | Evidencia | Impacto | Corrección mínima |
|---|---|---|---|---|---|---|
| PR-01 | P3 | `docs/SPEC_BASELINE.md:10`; manuscrito 228–229 | WebAuthn está congelado en la CR del 26-05-2026, ya sustituida por la Recommendation del 25-08-2026. | La revisión exacta está declarada; no se afirma conformidad con la versión actual. | Riesgo editorial de que el lector confunda baseline con estado vigente. | Explicar que la CR es el baseline congelado y citar también la Recommendation vigente. |
| PR-02 | P3 | `SUBMISSION_CHECKLIST.md:23-26` | Faltan autores, afiliaciones, plantilla, formularios, DOI y compliance final. | Los ítems siguen abiertos. | Impide un envío administrativo inmediato. | Completar los campos del venue elegido. |
| PR-03 | P3 | Alcance del encargo | No hay venue objetivo. | No se proporcionó call ni políticas. | No se pueden verificar fit, deadline, anonimización, fees, política de IA o indexación. | Elegir venue y ejecutar review específico. |

No se encontraron bloqueantes técnicos o de integridad.

## 3 Matriz claim evidence

| Afirmación central | Evidencia requerida | Evidencia observada | Veredicto |
|---|---|---|---|
| Login correcto puede coexistir con pérdida conductual en los controles | Aserción firmada y oráculo ejecutado | 512/5.120 casos con assertion PASS y `largeBlob` FAIL; witness firmado | Supported |
| El resultado depende de la ruta | Comparaciones pareadas | 14 comparaciones registradas y reproducidas | Supported |
| Identidad, clave, aserción y UV sobreviven importaciones completadas | Transcript source-bound y firma válida | 5.120 transcripts primarios verificados | Supported |
| `largeBlob` se conserva o pierde según el control | Observación del navegador no reescribible | 704 PASS, 512 FAIL; 5.120 witnesses verificados | Supported |
| PRF y `credBlob` positivos se preservan | Ejecución con estado de extensión inyectable | La interfaz no lo permite; el paper usa `NOT_EVALUABLE` | Not claimed |
| C2 cubre robustez registrada | Casos raw por familia | 80 casos, diez familias, ocho estratos | Supported |
| C3 prueba durabilidad o crash recovery | Store durable y caídas reales | Sólo máquina de estados en memoria; claim prohibido | Not claimed |
| C3 simula atomicidad e idempotencia | Estado y retry registrados | 960 secuencias; 832 PASS y 128 FAIL deliberados | Supported |
| HPKE RFC 9180 interopera funcionalmente | Dos implementaciones y ambas direcciones | Ambas direcciones pasan | Supported |
| El parser externo Bitwarden conserva el documento | Round trip de versión/revisión fijada | Igualdad semántica verdadera | Supported |
| El híbrido constituye CXP-PQC | Perfil registrado y evaluación normativa | Sólo round trip exploratorio; claim prohibido | Not claimed |
| El release deriva las cifras publicadas desde raw | Recomputación y regeneración | 4 resúmenes y 7 salidas reproducidos | Supported |

La afirmación más fuerte defendible es: **el harness detecta y conserva evidencia
auditable de pérdidas semánticas deliberadas en controles sintéticos versionados;
no caracteriza proveedores reales**.

## 4 Verificación numérica

| Valor publicado | Recalculado | Fuente primaria | Match | Nota |
|---:|---:|---|---|---|
| 6.144 intentos C1 | 6.144 | JSONL C1 full | Sí | 3.072 celdas credencial×ruta, dos ejecuciones |
| 5.120 importados | 5.120 | JSONL C1 full | Sí | Todos con transcript y witness |
| 1.024 rechazados | 1.024 | JSONL C1 full | Sí | Sin ceremonia |
| 2.304 PASS, 37,50% | 2.304/6.144 = 37,50% | JSONL C1 full | Sí | Yield del diseño, no tasa poblacional |
| 512 false reassurance, 10,00% | 512/5.120 = 10,00% | JSONL C1 full | Sí | Sólo `uv`/`largeBlob` ejecutados |
| 1.344 degradación silenciosa, 26,25% | 1.344/5.120 = 26,25% | JSONL C1 full | Sí | Denominador importado |
| 704/512 `largeBlob` PASS/FAIL | 704/512 | JSONL C1 full | Sí | 1.216 casos aplicables |
| 80 C2; 64 rechazados | 80; 64 | JSONL C2 | Sí | Familias no agrupadas en estimando |
| 960 C3; 832/128 atomicity PASS/FAIL | 960; 832/128 | JSONL C3 | Sí | Simulación en memoria |
| 96 grupos ruta×estrato | 96, todos N=64 | JSONL C1 full | Sí | Los 96 son homogéneos; 18 vectores de resultado |

## 5 Lentes de reviewer

**Métodos y estadística.** Las unidades, denominadores y exclusiones están
registrados. No se trata la repetición como independencia. La matriz de 96 celdas
es el resultado principal y los porcentajes son design-weighted. No hay inferencia
poblacional ni intervalos impropios.

**Dominio técnico y seguridad.** El threat model separa endpoint confiable,
canal, HPKE base y ausencia de autenticación del exportador. Los challenges usan
nonce fresco, domain separation y source binding. El segundo challenge compromete
la primera ceremonia y las observaciones de extensión. La prueba adversarial de
reescritura coordinada falla sin la clave privada.

**Sistemas y reproducibilidad.** Dependencias, navegador, CDP, commit y protocolo
están fijados. El ZIP no contiene entradas duplicadas ni artefactos históricos.
El verificador decide auditorías por el contenido v1.5, no por flags removibles
del manifest. Tests: 70/70.

**Meta-review.** El blind review fue Borderline porque no podía inspeccionar la
cadena probatoria. El artifact review fue Accept. La síntesis Weak Accept conserva
la limitación de validez externa sin descontar una implementación verificable.

**Machine learning, cualitativo y revisión sistemática.** No aplicables. La
revisión de literatura es contextual, no una systematic review.

## 6 Fortalezas verificadas

- Dos ceremonias WebAuthn y 10.400 challenges únicos en calibración más full.
- 5.200 witnesses de extensión verificados públicamente.
- Rechazo efectivo de transcript reassignment, key substitution, mutación de
  extensiones, divergencia raw-summary, entradas duplicadas y entradas no declaradas.
- Separación explícita entre conducta ejecutada, representación no ejecutable y
  marcadores de formato.
- Versionado y límites precisos para CXF, CXP Working Draft, HPKE y WebAuthn.
- Reproducción byte a byte de JSON, Markdown y CSV administrados.
- DOCX y PDF renderizados en cinco páginas sin clipping, overlaps o tablas rotas.

## 7 Evidencia o experimentos faltantes

| Prioridad | Evidencia | Claim habilitado | Esfuerzo | Requerido para aceptar claims actuales |
|---|---|---|---|---|
| Alta | Adaptador identificado de proveedor o segunda implementación CXP | Validez externa más allá de controles | Alto | No |
| Alta | Autenticador/CTAP que permita inyectar PRF y `credBlob` | Preservación conductual positiva de esas extensiones | Alto | No; hoy es `NOT_EVALUABLE` |
| Media | Store durable con kill/restart y recovery | Durabilidad y crash recovery | Medio/alto | No; esos claims están prohibidos |
| Media | Entorno SPC con instrumento de pago | Conducta del marcador payments | Alto | No |
| Baja | Diff/auditoría contra WebAuthn L3 Recommendation | Baseline normativo vigente | Bajo/medio | No para el baseline congelado |

## 8 Plan mínimo de revisión

**Blockers:** ninguno técnico.

**Revisiones mayores:** ninguna para las afirmaciones actuales. Se requiere
evidencia externa antes de ampliar claims a proveedores o implementaciones reales.

**Revisiones menores:** añadir autores/afiliaciones, venue y declaraciones;
explicar CR congelada frente a Recommendation vigente; depositar el ZIP y registrar
DOI; ejecutar compliance PDF del venue.

**Claims a retirar o debilitar:** ninguno adicional. Mantener prohibidos provider
prevalence, CXP normativo completo, PRF/`credBlob` positivos, SPC, durabilidad,
crash recovery, vulnerabilidad y novedad.

**Artefactos a añadir:** metadata del venue, DOI y formularios, no nueva evidencia
interna.

## 9 Decisiones contrafactuales

- **Sólo manuscrito:** Borderline, confianza 3/5.
- **Manuscrito más artefactos:** Weak Accept, confianza 4/5.
- **Venue de artifact/methods compatible:** Weak Accept a Accept, sujeto a formato.
- **Venue que exige impacto en productos desplegados:** Weak Reject sin adaptador externo.
- **Tras el experimento más valioso, un proveedor/adaptador independiente:** Accept
  si reproduce al menos un contraste de ruta o extensión con los mismos oráculos.

## 10 Preguntas de defensa

1. ¿Qué propiedad adicional prueba la segunda firma y qué no prueba frente a un
   generador de evidencia malicioso?
2. ¿Por qué 6.144 ejecuciones no son 6.144 observaciones independientes?
3. ¿Cómo cambiarían los porcentajes si se reponderaran rutas o estratos?
4. ¿Qué resultados están determinados por las políticas de control?
5. ¿Por qué una aserción válida no prueba preservación de PRF o `credBlob`?
6. ¿Qué diferencia hay entre parseo CXF, interoperabilidad de formato y flujo de proveedor?
7. ¿Qué autentica HPKE base y qué identidad deja sin autenticar?
8. ¿Por qué C3 no permite afirmar durabilidad aunque sus retries converjan?
9. ¿Cómo impide v0.7.1 que un atacante quite los flags de auditoría del manifest?
10. ¿Qué revisión normativa sería necesaria para pasar de la CR WebAuthn congelada a la Recommendation?
11. ¿Qué resultado mínimo de un proveedor independiente cambiaría la validez externa?
12. ¿Qué elementos del estudio fueron definidos después de inspeccionar datos anteriores?

## 11 Recomendación operacional

`SUBMIT AFTER MINOR REVISION`

