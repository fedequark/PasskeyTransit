# Remediación de la segunda revisión por pares

Fecha: 2026-09-23

Versión corregida: PasskeyTransit v0.4.0

Protocolo: passkeytransit-semantic-preservation-v1.2

## Resultado

Los cuatro señalamientos de la segunda revisión quedaron corregidos y la evidencia fue regenerada desde un árbol Git limpio. La versión v0.4.0 se presenta como una replicación correctiva posterior a la inspección de v1.1, no como una confirmación preregistrada independiente.

## Desafíos WebAuthn

Cada ceremonia importada usa ahora un desafío criptográficamente aleatorio de 32 bytes. El verificador independiente comprueba que el desafío firmado coincide con el desafío esperado y con el identificador del intento. El auditor rechaza desafíos cortos, duplicados o desvinculados.

La campaña de calibración y la campaña completa produjeron 5.200 ceremonias importadas. El auditor verificó 5.200 desafíos distintos y 5.200 transcripciones vinculadas al intento correspondiente. También confirmó 1.040 rechazos previos a la ceremonia.

## Estimando de falsa tranquilidad

El estimando principal incluye sólo fallos de oráculos conductuales ejecutables: UV, PRF con UV, PRF sin UV, largeBlob y credBlob. Bajo esa definición, 2.048 de 5.120 importaciones combinaron un login correcto con al menos un fallo conductual, para una tasa de 40,00%.

El marcador de pagos se declara por separado como comprobación de formato sin ceremonia Secure Payment Confirmation. Una sensibilidad inclusiva que añade ese marcador produjo 2.304 de 5.120 casos, o 45,00%. El manuscrito y las tablas informan ambas cantidades y explican la diferencia de alcance.

## Terminología y alcance CXP

El manuscrito identifica explícitamente v1.2 como una replicación correctiva posterior a la inspección. Además, la descripción de CXP se limita a lo observado: el Working Draft define parámetros HPKE, pero no incluye un miembro `enc` para la clave encapsulada, no define miembros de esquema para el challenge firmado que describe de forma narrativa y no concreta por completo el mapeo HPKE a ZIP/JWE. No se afirma una ausencia general de campos HPKE.

## Verificación

- Pruebas automatizadas: 61 aprobadas.
- Campaña C1 completa: 6.144 intentos; 5.120 importados; 1.024 rechazados.
- Preservación semántica completa: 2.304 de 6.144, o 37,50%.
- Degradación silenciosa entre importaciones: 1.344 de 5.120, o 26,25%.
- Falsa tranquilidad conductual: 2.048 de 5.120, o 40,00%.
- Sensibilidad con marcador de pagos: 2.304 de 5.120, o 45,00%.
- Auditoría de release: hashes de archivo y entradas correctos; 5.200 desafíos únicos; sin discrepancias; resultado `verified: true`.
- Revisión visual: las cinco páginas renderizadas desde el DOCX y las cuatro páginas del PDF fueron inspeccionadas sin defectos de corte, solapamiento, tablas rotas ni glifos ausentes.

El paquete reproducible se encuentra en `releases/v0.4.0/` y conserva las versiones v0.2 y v0.3 sin cambios.
