# La misma clave, distintas garantías
## Preservación de propiedades de seguridad en la migración de passkeys

[Nombre del autor] · [Afiliación] · [correo electrónico]

> RESULTADOS SIMULADOS. Este documento es un prototipo de paper. Las implementaciones, mediciones, divergencias y vulnerabilidades descritas son inventadas, aunque técnicamente verosímiles; no constituyen evidencia sobre productos reales.

## Resumen

Credential Exchange Format (CXF) y Credential Exchange Protocol (CXP) buscan permitir la transferencia segura de passkeys y otras credenciales entre credential providers. Aunque estos mecanismos protegen el transporte y estandarizan la representación de las credenciales, no está claro si una passkey conserva sus propiedades funcionales y de seguridad cuando cambia de custodio.

Presentamos el primer estudio sistemático —hipotético— sobre preservación semántica en la migración de passkeys. Definimos un modelo de equivalencia en tres niveles: identidad criptográfica, equivalencia funcional y equivalencia de seguridad. A partir de este modelo desarrollamos PasskeyTransit, un framework de differential testing que genera credenciales sintéticas, ejecuta migraciones y verifica las credenciales importadas mediante ceremonias WebAuthn y extensiones como PRF, hmac-secret, largeBlob y credBlob.

Evaluamos cinco implementaciones mediante 1.248 credenciales sintéticas y 18.720 rutas de migración. Aunque el 98,1 % conservó la capacidad básica de autenticación, sólo el 72,6 % preservó todas las propiedades funcionales aplicables. Encontramos 43 divergencias, incluyendo pérdida silenciosa de extensiones, importaciones no idempotentes, degradaciones durante downgrades y resultados PRF inconsistentes después de migraciones múltiples.

**Palabras clave—** passkeys, WebAuthn, CXF, CXP, credential migration, differential testing, PRF.

# 1. Introducción

Las passkeys utilizan criptografía de clave pública para reemplazar contraseñas y proporcionar autenticación resistente al phishing. En WebAuthn, el relying party conserva la clave pública y la clave privada permanece bajo control de un authenticator o credential provider.

La expansión de passkeys sincronizadas introdujo un problema de portabilidad. Una persona que cambia de password manager necesita transferir credenciales sin exportar claves privadas mediante archivos de texto inseguros y sin registrar manualmente una passkey nueva en cada servicio.

FIDO Alliance desarrolló CXF, que define la representación de las credenciales, y CXP, que define el intercambio protegido entre proveedores. CXF 1.0 figura como Proposed Standard, mientras CXP continúa como Working Draft [1]. Apple y otros ecosistemas comenzaron a implementar mecanismos de intercambio [2].

La confidencialidad del transporte sólo responde una parte del problema. Una passkey importada puede generar firmas válidas y, aun así, perder PRF, blobs asociados, soporte para pagos, restricciones de exportación, información de custodia o semántica de recuperación.

**Pregunta central—** ¿Qué significa que una passkey siga siendo “la misma” después de cambiar de credential provider?

## 1.1. Contribuciones

- Formalizamos equivalencia criptográfica, funcional y de seguridad.
- Introducimos credential clone set para modelar custodios capaces de usar una clave.
- Presentamos PasskeyTransit y un corpus reproducible de credenciales sintéticas.
- Evaluamos migraciones directas, round trips y rutas de múltiples proveedores.
- Proponemos requisitos de criticidad, atomicidad, idempotencia y consentimiento.

# 2. Antecedentes

## 2.1. WebAuthn

Durante el registro, un authenticator crea un par (skC, pkC). Una assertion demuestra posesión de skC mediante una firma sobre authenticatorData y el hash de clientDataJSON. El RP verifica la firma con pkC. Además de las claves, una passkey incluye credential ID, RP ID, user handle, metadata presentable y extensiones.

`σ = Sign_skC(authenticatorData || H(clientDataJSON))`

## 2.2. Credential Exchange Format

CXF representa una passkey con credentialId, rpId, username, userDisplayName, userHandle, una clave privada PKCS#8 y extensiones FIDO2 opcionales [3].

```
Passkey = {
  type: "passkey", credentialId, rpId,
  username, userDisplayName, userHandle,
  key, optional fido2Extensions
}
```

La especificación contempla PRF/hmac-secret, credBlob, largeBlob y Secure Payment Confirmation. Excluye de la exportación passkeys con signature counter distinto de cero; los importadores usan contador cero.

## 2.3. Credential Exchange Protocol

CXP permite que el importador solicite una transferencia especificando versión, parámetros HPKE, modo, tipos y extensiones conocidas. El exportador responde con un payload cifrado. El documento protege la transferencia, pero no modela completamente amenazas introducidas por los propios providers [4].

## 2.4. Credential clone set

Definimos CloneSet(C,t) como el conjunto de providers capaces de producir una assertion válida para C en el instante t. Una migración puede transformar {A} en {A,B}; salvo borrado o rotación, la operación amplía la cantidad de custodios.

`CloneSet(C,t) = { p | p puede usar la clave de C en t }`

# 3. Modelo de preservación

Representamos una passkey como C=(I,K,F,S), donde I contiene identidad y binding; K material criptográfico; F capacidades funcionales; y S propiedades operacionales y de seguridad. Una migración M produce C'=M(C,A,B).

## 3.1. Equivalencia criptográfica

C ≡c C' cuando se conservan clave pública, credential ID, RP ID y user handle, y una assertion de C' es aceptada por el registro original.

`pk(C)=pk(C') ∧ id(C)=id(C') ∧ rpId(C)=rpId(C')`

## 3.2. Equivalencia funcional

C ≡f C' cuando C ≡c C' y toda operación soportada por ambos providers produce un resultado equivalente. Para PRF exigimos igualdad para todos los salts del conjunto de prueba.

`∀s ∈ Salts: PRF(C,s) = PRF(C',s)`

## 3.3. Equivalencia de seguridad

C ≡s C' cuando se conserva la equivalencia funcional, no aparecen custodios no autorizados, las degradaciones son explícitas, se respetan restricciones críticas y la migración es atómica o recuperable.

Una degradación puede ser explícita o silenciosa, funcional u operacional, transitoria o persistente.

# 4. Preguntas de investigación

**RQ1.** ¿Con qué frecuencia se preserva la identidad criptográfica?

**RQ2.** ¿Qué propiedades se pierden en migraciones directas y multihop?

**RQ3.** ¿Cómo se manejan desconocidos, downgrades, duplicados y fallos?

**RQ4.** ¿Puede observarse cómo cambia el conjunto de custodios?

# 5. PasskeyTransit

PasskeyTransit integra un generador, RP local, providers instrumentados, mutador, oráculos y comparador semántico. Cada credencial conserva un ground truth con claves, IDs, resultados PRF, blobs y propiedades esperadas.

## 5.1. Proveedores

| ID | Perfil |
|---|---|
| P1 | Referencia estricta |
| P2 | Referencia permisiva |
| P3 | Legacy sin extensiones |
| P4 | Prototipo Rust |
| P5 | Prototipo de plataforma |

*Tabla 1. Implementaciones anonimizadas y simuladas.*

## 5.2. Mutaciones y oráculos

El mutador elimina o duplica campos, trunca base64url y PKCS#8, altera RP IDs, introduce versiones futuras y crea credenciales duplicadas. Los casos se minimizan automáticamente.

Aplicamos oráculos de conformidad, correspondencia de claves, verificación WebAuthn end-to-end, equivalencia de extensiones y comparación diferencial.

## 5.3. Rutas

```
A → B
A → B → A
A → B → C
A → B → C → A
```

# 6. Metodología

## 6.1. Corpus

| Categoría | N |
|---|---:|
| ES256 básicas | 240 |
| PRF | 208 |
| hmac-secret | 160 |
| largeBlob | 160 |
| credBlob | 160 |
| Payments | 80 |
| Extensiones múltiples | 120 |
| Desconocidas | 120 |
| Total | 1.248 |

*Tabla 2. Composición del corpus sintético.*

## 6.2. Ejecuciones

Ejecutamos 18.720 rutas: 6.240 migraciones directas, 6.240 round trips y 6.240 rutas de tres o más providers. Inyectamos fallos tras la aprobación, creación del payload, descifrado, persistencia parcial y antes del commit.

Cada divergencia fue clasificada como permitida, ambigua, degradación visible, degradación silenciosa, violación normativa o violación de seguridad. El acuerdo interevaluador simulado fue κ=0,84.

# 7. Resultados simulados

## 7.1. RQ1: identidad criptográfica

El 98,1 % de las credenciales importadas conservó identidad criptográfica completa. En 61 casos, la importación fue aceptada pero la credencial resultante no produjo una assertion válida.

| Resultado | Porcentaje |
|---|---:|
| Identidad preservada | 98,1 % |
| Rechazo correcto | 1,2 % |
| No autenticable | 0,5 % |
| Asociación incorrecta | 0,2 % |

*Tabla 3. Resultado criptográfico de las importaciones.*

Las causas incluyeron claves no persistidas, normalización del credential ID, asociación errónea de RP ID y reemplazo ambiguo. Los casos de RP ID incorrecto sólo aparecieron con inputs mutados que debían rechazarse.

## 7.2. RQ2: preservación funcional

Sólo el 72,6 % mantuvo todas sus propiedades funcionales aplicables. Probar un login posterior no detectó pérdida de PRF, blobs o semántica de pagos.

| Propiedad | Preservación |
|---|---:|
| Autenticación | 98,1 % |
| User verification | 96,8 % |
| PRF | 81,4 % |
| hmac-secret | 79,7 % |
| credBlob | 89,1 % |
| largeBlob | 83,6 % |
| Payments | 68,3 % |

*Tabla 4. Preservación funcional por propiedad.*

## 7.3. Pérdidas multihop

La preservación descendió a medida que aumentó la cantidad de saltos. Una propiedad descartada por un provider intermedio no pudo reconstruirse posteriormente.

| Ruta | Preservación |
|---|---:|
| A → B | 88,7 % |
| A → B → A | 84,2 % |
| A → B → C | 76,9 % |
| A → B → C → A | 69,8 % |

*Tabla 5. Efecto acumulativo de múltiples migraciones.*

## 7.4. RQ3: extensiones y downgrade

De 2.400 casos con extensiones desconocidas, el 31 % fue preservado como opaco, 27 % rechazado y 42 % descartado. Sólo el 18 % de los descartes produjo advertencia visible.

El 14,8 % de los downgrades aceptados perdió al menos una propiedad; en el 9,3 % la pérdida fue silenciosa. Las implementaciones discreparon sobre qué condiciones debían abortar la migración.

## 7.5. Idempotencia y atomicidad

Dos providers detectaron importaciones repetidas, uno actualizó metadata, uno creó duplicados visibles y otro produjo resultados dependientes del orden. De 3.000 migraciones interrumpidas, 74,1 % fue atómica; 18,6 % dejó estado parcial recuperable; 5,9 % generó duplicados tras retry; y 1,4 % requirió reparación manual.

## 7.6. RQ4: custodios

El provider de origen continuó autenticando en todos los casos y el destino en el 98,1 %. El RP no recibió señal de que la clave había cambiado de custodio. Restaurar un backup del origen recuperó copias eliminadas previamente.

En cuatro implementaciones, la UI no distinguió copiar, transferir, respaldar o migrar conservando el origen. Operacionalmente, el proceso se comportó como clonación.

## 7.7. Divergencias

| Categoría | N |
|---|---:|
| Pérdida silenciosa | 14 |
| No idempotente | 8 |
| Downgrade ambiguo | 7 |
| PRF inconsistente | 5 |
| Fallos parciales | 4 |
| Metadata en logs | 3 |
| Confusión de cuentas | 2 |
| Total | 43 |

*Tabla 6. Divergencias únicas encontradas.*

# 8. Casos representativos

## 8.1. Login correcto, PRF incorrecto

Una credencial migrada continuó autenticando, pero PRF(C,s) ≠ PRF(C',s). Una aplicación que utilizaba PRF para descifrar información perdió acceso a sus datos. El defecto no era observable mediante un test de login.

## 8.2. Extensión futura descartada

P2 omitió una extensión desconocida. Al reexportar hacia un provider que sí la soportaba, la información ya se había perdido. La compatibilidad sintáctica convirtió una degradación local en pérdida permanente.

## 8.3. Retry con duplicados

P5 persistió una passkey y falló antes de confirmar. El retry creó una segunda entrada con el mismo credential ID y la misma clave, pero un item ID diferente. La UI no permitía identificar cuál correspondía a la operación original.

## 8.4. Confusión visual

Dos credenciales con nombres Unicode visualmente similares fueron agrupadas bajo la misma etiqueta aunque tenían user handles diferentes. No hubo bypass criptográfico, pero sí riesgo de selección incorrecta de cuenta.

# 9. Discusión

Nuestros resultados ilustran que C ≡c C' no implica C ≡f C', y que C ≡f C' tampoco implica C ≡s C'. La interoperabilidad sintáctica y la autenticación básica no prueban preservación semántica.

## 9.1. Criticidad de extensiones

Proponemos clasificar extensiones como informativas, funcionales, críticas para disponibilidad, críticas para seguridad o críticas para identidad.

| Clase | Tratamiento |
|---|---|
| Informativa | Puede descartarse |
| Funcional | Advertir |
| Disponibilidad crítica | Consentir o rechazar |
| Seguridad crítica | Abortar |
| Identidad crítica | No transformar |

*Tabla 7. Política propuesta de criticidad.*

## 9.2. Manifest de propiedades

```
{
  "required": ["authentication", "prf"],
  "optional": ["largeBlob"],
  "custody": {"operation": "copy"},
  "downgradePolicy": "abort"
}
```

El importador debería responder con propiedades preservadas, descartadas y cambios de custodia antes del commit.

## 9.3. Atomicidad

`prepare → validate all → persist atomically → verify usability → commit`

Cuando no sea posible garantizar atomicidad, el resultado debe informarse por credencial: imported, rejected, degraded, rolled-back o unknown.

## 9.4. Migración frente a rotación

Copiar la clave maximiza compatibilidad, pero conserva el riesgo de copias anteriores. Una alternativa es autenticar con la credencial importada, registrar una nueva, verificarla y revocar la anterior. Esta rotación asistida ofrece una frontera de custodia más clara.

# 10. Recomendaciones

## 10.1. Para CXF/CXP

- Definir copy, transfer y backup.
- Permitir criticidad de extensiones.
- Añadir un manifest de propiedades.
- Prohibir degradaciones críticas silenciosas.
- Definir idempotency keys y resultados parciales.
- Vincular consentimiento con el conjunto exportado.
- Establecer reglas normativas de downgrade.
- Emitir un receipt verificable de migración.

## 10.2. Para credential providers

- Validar la correspondencia de claves.
- Ejecutar pruebas WebAuthn y PRF posteriores.
- Mostrar propiedades no soportadas.
- Evitar logging de IDs sensibles.
- Hacer la importación idempotente.
- Distinguir copia de transferencia.
- Mostrar reexportabilidad y custodios conocidos.

# 11. Limitaciones

El estudio hipotético evalúa cinco implementaciones y utiliza credenciales sintéticas. Algunas propiedades de custodia no son observables externamente: no puede demostrarse que un provider eliminó backups o copias internas. CXF/CXP continúan evolucionando y no realizamos un estudio con participantes. Finalmente, todas las cifras de este prototipo son inventadas y no describen productos reales.

# 12. Consideraciones éticas

Una evaluación real debe utilizar cuentas, dispositivos y credenciales controlados por los investigadores, limitar cargas, evitar vaults personales y comunicar defectos mediante responsible disclosure. Los artifacts públicos deberían contener semillas y generadores, no claves privadas reales.

# 13. Trabajo futuro

Las siguientes direcciones incluyen análisis formal de CXP, privacidad estructural frente a orchestrators, rotación asistida, receipts de custodia y estudios de usabilidad sobre las diferencias entre copiar, transferir, respaldar y revocar.

# 14. Conclusión

Una passkey importada puede conservar clave, credential ID, RP ID y capacidad de autenticación, y aun así perder funcionalidades o cambiar garantías de seguridad. La propiedad relevante no es solamente key_before = key_after, sino que las propiedades requeridas estén incluidas entre las preservadas.

CXF y CXP proporcionan una base importante para portabilidad, pero la interoperabilidad sintáctica debe complementarse con propiedades explícitas, degradaciones verificables y semántica de custodia. Migrar de forma segura no consiste sólo en proteger una clave durante el transporte: consiste en preservar o renegociar conscientemente las garantías asociadas a ella.

# Referencias

[1] FIDO Alliance. Credential Exchange Specifications. https://fidoalliance.org/download-credential-exchange-specifications/

[2] Apple. What’s New in Passkeys. WWDC 2025. https://developer.apple.com/videos/play/wwdc2025/279/

[3] FIDO Alliance. Credential Exchange Format 1.0. https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html

[4] FIDO Alliance. Credential Exchange Protocol. https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html

[5] W3C. Web Authentication Level 3. https://www.w3.org/TR/webauthn-3/

[6] IETF. RFC 9180: Hybrid Public Key Encryption. https://www.rfc-editor.org/rfc/rfc9180

[7] Apple. ASCredentialImportManager. https://developer.apple.com/documentation/authenticationservices/ascredentialimportmanager

[8] Google. Credential Manager. https://developer.android.com/identity/credential-manager
