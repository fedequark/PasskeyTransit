# Preservación semántica en migraciones de passkeys con CXF y CXP: controles reproducibles y un caso abierto de proveedor

Versión 0.8, borrador exploratorio de 2026-10-02. Conserva por separado los
resultados de la release v0.7.1 y añade las fases 14 y 15. No reemplaza la
release publicada ni constituye una nueva muestra de proveedores.

## Resumen

Estudiamos si una passkey que continúa autenticando después de un intercambio
conserva además su identidad, extensiones y garantías operacionales. Presentamos
PasskeyTransit, un harness reproducible para CXF, un binding experimental
CXP/HPKE, WebAuthn, mutaciones y una simulación transaccional en memoria.
La unidad descriptiva
principal es la matriz completa de
96 celdas
ruta×estrato. Para comprobar estabilidad y evidencia técnica, la campaña ejecutó
6,144 intentos sobre 256 credenciales,
12 rutas y dos repeticiones con controles y autenticadores
virtuales Chromium. El diseño contiene
3,072
celdas credencial×ruta, ejecutadas dos veces y resumidas en
96 grupos.
Ninguna unidad fue muestreada de una población real y los porcentajes agregados
son proporciones ponderadas por este diseño balanceado.
Se importaron 5,120 intentos
y se rechazaron 1,024 antes de la ceremonia. Las 5,120
aserciones WebAuthn ejecutadas fueron aceptadas; 512 intentos
(10.00%) combinaron
login correcto con el fallo de un oráculo conductual realmente ejecutado en el
navegador (`uv` o `largeBlob`). Las pérdidas de representación no ejecutables de
PRF o `credBlob` aparecieron en 1,792 intentos
(35.00%); esta categoría se solapa con la
anterior. La unión de fallos no relacionados con pagos fue
40.00%
(2,048/5,120). Al
añadir el marcador de pagos, que es sólo una comprobación de formato sin
ceremonia SPC, la sensibilidad total fue 45.00%
(2,304/5,120). El rendimiento
de intentos con `PASS` completo observable fue 37.50%
(2,304/6,144). Estos
porcentajes son ponderaciones del diseño sintético, no tasas de productos ni
prevalencia real. PRF y preservación positiva de `credBlob` permanecen no
evaluables por límites de la interfaz CDP en esa campaña. Un seguimiento
posterior intercambió documentos con dos implementaciones propias del binding
experimental y ejecutó un control de pérdida PRF con autenticadores virtuales.
En un caso seleccionado de proveedor abierto, Fenko Vault 0.12.0, dos
importaciones CXF repetidas produjeron autenticación WebAuthn válida, pero el
PRF obtenido en el navegador no coincidió con el control derivado de las
semillas CXF de origen y la exportación omitió ese estado. Se verificaron 16
aserciones firmadas y seis vínculos de observación PRF. Este caso no mide
frecuencia de fallos entre proveedores; CXP entre proveedores y preservación
positiva de PRF entre navegadores siguen sin evaluar.

## 1. Introducción

CXF estandariza la representación de credenciales [1] y CXP propone su transporte
protegido. Sin embargo, aceptar un documento e incluso completar una aserción
WebAuthn no demuestra por sí solo que sobrevivan todas las propiedades de una
passkey. Modelamos la credencial como `C=(I,K,F,S)`: identidad, material
criptográfico, funciones observables y garantías operacionales.

La proposición falsable es que una importación aceptada y un login correcto son
insuficientes para establecer preservación semántica completa. No formulamos
afirmaciones de novedad ni sobre implementaciones comerciales no examinadas.

## 2. Trabajo relacionado

La arquitectura de credenciales FIDO multidispositivo sitúa disponibilidad y
recuperación en la sincronización del proveedor [7]. Los estudios empíricos
recientes se concentran en experiencia de usuario y comportamiento de relying
parties [8], despliegue y seguridad de sitios WebAuthn [9], o diferencias de
confianza entre credenciales ligadas al dispositivo y sincronizadas [10]. Estas
líneas no miden conjuntamente identidad, correspondencia de clave, extensiones,
dependencia de ruta, atomicidad e idempotencia durante intercambio CXF/CXP. El
presente trabajo cubre esa brecha como método de medición sobre controles
sintéticos y un caso seleccionado de proveedor abierto; no estima prevalencia
de comportamiento entre proveedores.

## 3. Método

El protocolo `passkeytransit-semantic-preservation-v1.5` fue congelado antes de
esta replicación correctiva posterior a la inspección de v1.2. No la presentamos
como confirmación preregistrada independiente. El corpus contiene 256 credenciales ES256,
32 en cada uno de ocho estratos: básica, PRF con UV, PRF sin UV, `largeBlob`,
`credBlob`, marcador de pagos, combinación de extensiones y miembro opcional
futuro. Doce rutas cubren migración directa, round trip y multihop.

Cada salto serializa un documento CXF validado y lo transporta mediante HPKE
base X25519/HKDF-SHA256/AES-128-GCM [3]. El navegador importa el resultado en un
autenticador virtual y ejecuta `navigator.credentials.get()`. Un verificador
Python independiente de la ceremonia recompone un desafío derivado de un nonce
aleatorio y de un contexto canónico que incluye intento, credencial, ruta,
repetición, ejecución, hash de SPKI, hash de user handle, RP ID y origen. Una
segunda ceremonia firma otro desafío que compromete el primer challenge y el
hash canónico de las observaciones de extensión, incluida `largeBlob`. El
verificador cruza esos valores con la fila, reproduce hashes de artefactos y
comprueba flags UP/UV, ambas firmas ES256 y contador cero [4].

Los oráculos devuelven `PASS`, `FAIL`, `NOT_APPLICABLE` o `NOT_EVALUABLE`.
Separadamente clasificamos estado de ejecución, preservación semántica y
evaluación normativa. Las 96 celdas ruta×estrato son un censo exacto del diseño
registrado: la matriz es el resultado principal. Los porcentajes son agregados
ponderados por el diseño y se informan sin intervalos de muestreo. Las
comparaciones de rutas son pareadas por credencial y repetición.

### 3.1. Seguimiento exploratorio posterior a la release

Las fases 14 y 15 se diseñaron tras inspeccionar resultados anteriores. La
primera usa dos implementaciones escritas en este proyecto para transportar
un documento CXF mediante el binding CXP experimental; compara el documento
recuperado, rechaza un ciphertext alterado y ejecuta por software el mapeo
WebAuthn PRF sobre semillas CXF. Un control separado crea una passkey con PRF
en un autenticador virtual Chromium, observa tres resultados PRF y una
aserción firmada tras importación CDP en otro autenticador. La interfaz CDP
no transfiere el secreto PRF.

El protocolo v2, fijado tras inspeccionar el código del proveedor candidato y
antes de ejecutar el caso completo, selecciona Fenko Vault 0.12.0 en el commit
`2d873fbe25257250de6e322e9d785b97b17a544f` [11]. Por eso el caso es
una comprobación dirigida de pérdida, no una muestra independiente. En dos
perfiles Edge nuevos, dos credenciales ES256 sintéticas por perfil ingresan
por la interfaz de importación CXF. La extensión original responde a
`navigator.credentials.get()` desde `localhost`; el verificador recalcula
identidad, desafío, origen, hash RP y firma ES256. Para cada resultado PRF, una
segunda aserción firma un desafío derivado del primer desafío y del hash del
resultado. El ensayo también importa una clave PKCS#8 inválida, repite una
importación, reinicia el perfil, vuelve a autenticar y exporta CXF desde la
interfaz del proveedor. Los informes conservan transcripciones públicas y
hashes, sin claves, semillas ni resultados PRF crudos.

La comparación del PRF de destino usa un control de software calculado desde
las semillas CXF de origen y el mapeo normativo. No existe una ceremonia PRF
WebAuthn de origen en este caso, por lo que no es una prueba de continuidad
positiva navegador a navegador.

## 4. Modelo de amenazas

El experimento protege la confidencialidad e integridad del payload frente a un
observador o modificador del canal que no posee la clave privada del importador.
El importador y los perfiles de control son componentes confiables e
instrumentados; no modelamos compromiso del endpoint, extracción de claves,
canales laterales ni engaño del usuario. El binding experimental rechaza mezcla
de solicitudes, modificación del contexto, downgrade y replay dentro del estado
local de la ejecución. HPKE base no autentica la identidad del exportador y el
ensayo no demuestra autorización del usuario, attestation del proveedor ni
persistencia global del estado antireplay.

## 5. Implementación del transporte

La implementación HPKE reproduce el vector oficial de RFC 9180 [3]. El Working
Draft CXP [2] define parámetros HPKE, pero no un miembro para la clave
encapsulada `enc` ni miembros de esquema para el challenge firmado que describe
su narrativa, y no concreta completamente el mapeo HPKE a ZIP/JWE.
Usamos una extensión experimental autenticada como AAD y no reclamamos
interoperabilidad CXP normativa completa.

Una segunda implementación, `cryptography 50.0.1` [5], intercambió ciphertexts
HPKE en ambas direcciones con PasskeyTransit. Un consumidor Node.js independiente
validó el envelope CXF, PKCS#8, SPKI, credential ID y `largeBlob` DEFLATE. El
ensayo híbrido ML-KEM-768+X25519 fue exitoso, pero permanece fuera del perfil
CXP y de los estimandos.


### 5.1. Implementación CXF externa

La librería Rust `credential-exchange-format` 0.4.0 de
Bitwarden, fijada al commit `0ee5516e4c0481ab6b0a68f8541fc39c3c3379b1`, parseó y
serializó un documento CXF con passkey y extensiones. El documento normalizado
conservó exactamente su hash SHA-256. Esta prueba establece interoperabilidad de
formato con una implementación abierta independiente; no ejecuta el flujo de un
producto ni autoriza afirmaciones sobre Bitwarden como proveedor.


## 6. Resultados

### 6.1. Campaña C1 con navegador

De 6,144 intentos, 5,120 fueron importados y 1,024
rechazados por el control `strict`. Identidad, correspondencia de clave pública,
aserción WebAuthn y UV pasaron en los intentos importados. Las dos repeticiones
produjeron resultados semánticos equivalentes.

| Clase semántica | N | Proporción |
|---|---:|---:|
| PASS | 2,304 | 37.50% |
| Degradación visible | 960 | 15.62% |
| Degradación silenciosa | 1,344 | 21.88% |
| No evaluable | 512 | 8.33% |
| Rechazo previo a ceremonia | 1,024 | 16.67% |

La proporción ponderada de degradación silenciosa dentro del diseño fue 26.25%
(1,344/5,120). `largeBlob` fue
observable en 1,216 casos aplicables: 704 pasaron y 512 fallaron según la ruta
de control. La pérdida en un intermediario persistió al volver a un destino
capaz, produciendo discordancias en comparaciones pareadas con el mismo destino.

### 6.2. Robustez C2

C2 ejecutó 80 casos: diez familias sobre ocho estratos. Se
rechazaron 64 casos por validación estructural, política de duplicados
o preservación estricta. Las familias se informan por separado; la clase normativa
se deriva del requisito aplicable y del resultado observado. No se calcula un
porcentaje agrupado.

### 6.3. Simulación de fallos C3

C3 ejecutó 960 secuencias y 1920 eventos sobre una máquina
de estados Python en memoria; no prueba almacenamiento durable ni recuperación
ante caída de proceso. En
832 secuencias (86.67%) hubo rollback completo
y el retry convergió a una copia. Las 128 fallas restantes fueron el control
positivo deliberado: `legacy` conservó un provisional en los dos puntos tardíos
y el retry creó un duplicado, haciendo fallar atomicidad e idempotencia.

### 6.4. Fase 14: intercambio experimental y control PRF

La implementación Node.js y la Python recuperaron el mismo documento CXF en
ambas direcciones del binding experimental, y el receptor rechazó un ciphertext
alterado. Los evaluadores de software de ambos runtimes coincidieron con las
semillas CXF preservadas y detectaron su eliminación. En Edge 154 y Chrome 154,
el control con autenticadores virtuales produjo PRF estable para la misma
entrada, diferente para otra, y autenticación firmada antes y después del
traslado. El PRF faltó después de la importación CDP. Es una prueba local del
oráculo de pérdida; ninguna de estas rutas ejecutó un proveedor CXP externo.

### 6.5. Fase 15: caso CXF de proveedor abierto

Fenko Vault importó dos credenciales sintéticas por repetición en dos perfiles
nuevos. La credencial básica y la que llevaba semillas CXF PRF firmaron
aserciones WebAuthn. Un verificador separado comprobó las 16 firmas retenidas,
incluidas seis aserciones que vinculan hashes de resultados PRF. La clave
inválida fue rechazada sin cambiar el recuento almacenado; la importación
duplicada se omitió; dos credenciales persistieron tras reiniciar el perfil y
una volvió a firmar. Estas observaciones se repitieron en 2/2 ejecuciones.

Para la credencial con PRF, la extensión devolvió un resultado estable con la
misma entrada y diferente con otra. El hash de ese resultado no coincidió con
el control calculado a partir de la semilla CXF de origen en 2/2 ejecuciones.
La exportación CXF retuvo los identificadores de credencial y los user handles,
pero omitió `fido2Extensions.hmacCredentials`; además produjo versión 0.0 y
un `userName` vacío donde el origen tenía `username`. La inspección del commit
fijado muestra que su importador omite `fido2Extensions` y el proveedor deriva
otro estado PRF de la clave de firma cuando no dispone de un campo propio [11].
Los resultados describen esta revisión y esta ruta seleccionada; las dos
repeticiones no representan dos proveedores ni una tasa de fallos.

## 7. Discusión

El experimento demuestra una capacidad del método: la autenticación funcionó
en los 5,120 intentos importados, incluidos aquellos en los que los
controles descartaron otras propiedades. Los 1,024 rechazos `strict`
detuvieron la importación antes de la ceremonia. Por tanto, un test de login
aislado no es un oráculo suficiente para migración semántica.

También observamos dependencia de ruta: un destino final sin pérdidas propias
no puede reconstruir material descartado por un intermediario. La declaración
pre-commit cambia además la clasificación de una misma pérdida de silenciosa a
visible, aun cuando el estado final de la credencial sea idéntico.

El caso Fenko concreta la distinción entre autenticación y función: el mismo
flujo de importación que permitió firmas válidas no conservó el estado PRF CXF
medido. El resultado PRF pertenece a `clientExtensionResults`, fuera de los
bytes firmados por el autenticador; la aserción adicional liga criptográficamente
un hash observado por el harness, pero no demuestra por sí misma que el cálculo
interno del proveedor siga el estándar. La fuente del control PRF fue software,
por lo que este caso no confirma migración PRF entre dos navegadores.

## 8. Limitaciones

- Los cuatro perfiles de la campaña C1 son controles sintéticos; el caso Fenko
  es un proveedor abierto seleccionado tras inspección de su código.
- CDP no permite inyectar HMAC/PRF ni `credBlob`; los casos positivos son
  `NOT_EVALUABLE`, nunca `PASS`.
- No ejecutamos Secure Payment Confirmation.
- El binding adicional de CXP es experimental y no resuelve autenticación de
  identidad del exportador en modo HPKE base.
- El ensayo PQC prueba disponibilidad criptográfica, no un perfil CXP-PQC.
- C3 es una simulación determinista en memoria, no una prueba de durabilidad.
- Los porcentajes agregados dependen de los pesos elegidos para rutas y estratos.
- No se permite inferir vulnerabilidades, prevalencia de fallos ni superioridad
  de productos a partir de estos controles.
- Las dos ejecuciones Fenko comprueban repetibilidad de una revisión y ruta;
  no son una muestra aleatoria ni un ensayo de otras versiones o proveedores.
- No se ejecutó CXP entre dos proveedores. Tampoco hubo PRF WebAuthn de origen
  y destino con las mismas semillas restauradas; ambos oráculos son
  `NOT_EVALUABLE` en el seguimiento.

## 9. Reproducibilidad

Los artefactos raw son JSONL inmutables; los derivados y manifiestos incluyen
hashes SHA-256 del protocolo, resultados, navegador y commit. La campaña C1 se
ejecutó con Chromium 153.0.4234.48 y Playwright
1.62.0 desde un árbol Git limpio. El
auditor de release recompone cada challenge a partir de un nonce aleatorio y del
contexto de la fila, liga la firma a la clave pública fuente, verifica RP ID,
user handle y origen, y verifica una segunda firma que compromete las
observaciones de extensión. Además recalcula resúmenes C1/C2/C3 desde los JSONL
y regenera resultados, tablas y manuscrito para compararlos con la release. El
repositorio incluye comandos de una sola operación para tests, C1, C2, C3,
interoperabilidad y regeneración de este análisis.

Las fases 14 y 15 quedan fuera de aquella release y tienen informes separados.
`./research.ps1 phase14` reproduce el intercambio propio y el control CDP;
`./research.ps1 phase15` construye Fenko desde el commit fijado, ejecuta sus
tests CXF y el caso en dos perfiles, y vuelve a verificar las transcripciones
públicas. El informe conservado es
`experiments/v2_exploratory/fenko_provider.json`, acompañado de
`fenko_verification.json`, el protocolo v2 y los hashes del código fuente,
build y navegador. El verificador independiente recompone firmas y vínculos
PRF; los recuentos de almacenamiento proceden de la observación del runner y
su consistencia se comprueba, pero el informe público no permite reconstruir
la base de datos privada del proveedor. El borrador v0.8 todavía no forma parte
de un archivo de release auditado como v0.7.1.

## 10. Conclusión

PasskeyTransit distingue compatibilidad sintáctica, autenticación básica y
preservación funcional, y simula garantías transaccionales. En los controles diseñados,
una aserción válida no basta para afirmar
que una passkey migrada conserva todas sus garantías. El paso necesario para
generalizar es ejecutar más rutas identificadas e independientes, manteniendo
los mismos oráculos y límites de afirmación. El caso externo confirma en una
ruta concreta que autenticar no garantiza conservar el PRF importado. La
interoperabilidad CXP de proveedores y la preservación positiva de PRF en una
migración navegador a navegador siguen pendientes de un entorno accesible.

## Referencias

1. FIDO Alliance, Credential Exchange Format v1.0 Proposed Standard Errata, 2026,
   https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html.
2. FIDO Alliance, Credential Exchange Protocol v1.0 Working Draft, 2024-10-03,
   https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html.
3. Barnes et al., Hybrid Public Key Encryption, RFC 9180, 2022,
   https://www.rfc-editor.org/rfc/rfc9180.
4. W3C, Web Authentication Level 3 Candidate Recommendation, 2026-05-26,
   https://www.w3.org/TR/2026/CR-webauthn-3-20260526/.
5. PyCA, `cryptography` HPKE API documentation,
   https://cryptography.io/en/latest/hazmat/primitives/hpke/.
6. Bitwarden, `credential-exchange` v0.4.0,
   https://github.com/bitwarden/credential-exchange/tree/v0.4.0.
7. FIDO Alliance, Multi-Device FIDO Credentials, 2022,
   https://fidoalliance.org/white-paper-multi-device-fido-credentials/.
8. Ramat et al., Passkeys in the Wild: A Systematic Study of FIDO2 User
   Experience Consistency Across Websites, SOUPS 2026,
   https://www.usenix.org/conference/soups2026/presentation/ramat.
9. Jannett et al., The State of Passkeys, USENIX Security 2026,
   https://www.usenix.org/conference/usenixsecurity26/presentation/jannett.
10. Büttner and Gruschka, Device-Bound vs. Synced Credentials: A Comparative
    Evaluation of Passkey Authentication, ICISSP 2025,
    https://arxiv.org/abs/2501.07380.
11. FenkoHQ, Passkey Vault 0.12.0, commit
    `2d873fbe25257250de6e322e9d785b97b17a544f`,
    https://github.com/FenkoHQ/passkey-vault/tree/2d873fbe25257250de6e322e9d785b97b17a544f.
