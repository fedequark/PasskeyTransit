from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify(summary_path: Path, manifest_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    summary, manifest = _load(summary_path), _load(manifest_path)
    expected = manifest.get("summary_sha256")
    if expected != _sha(summary_path):
        raise ValueError(f"summary hash does not match manifest: {summary_path}")
    if manifest.get("source_dirty") is not False:
        raise ValueError(f"evidence was not generated from a clean source tree: {manifest_path}")
    return summary, manifest


def _percent(value: float | None) -> str:
    return "NE" if value is None else f"{100 * value:.2f}%"


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _manuscript(results: dict[str, Any]) -> str:
    c1, c2, c3, interop = results["c1"], results["c2"], results["c3"], results["interop"]
    estimands = c1["estimands"]
    yield_result = estimands["preserving_migration_yield"]
    silent = estimands["silent_degradation_rate"]
    reassurance = estimands["false_reassurance_rate"]
    atomic_pass = c3["atomicity"]["PASS"]
    total_c3 = c3["failure_sequence_count"]
    external = results.get("external_cxf")
    external_text = ""
    if external:
        external_text = f"""

### 3.1. Implementación CXF externa

La librería Rust `credential-exchange-format` {external['adapter']['version']} de
Bitwarden, fijada al commit `{external['adapter']['source_revision']}`, parseó y
serializó un documento CXF con passkey y extensiones. El documento normalizado
conservó exactamente su hash SHA-256. Esta prueba establece interoperabilidad de
formato con una implementación abierta independiente; no ejecuta el flujo de un
producto ni autoriza afirmaciones sobre Bitwarden como proveedor.
"""
    return f"""# Migrar una passkey no basta: preservación semántica en controles CXF/CXP

## Resumen

Estudiamos si una passkey que continúa autenticando después de un intercambio
conserva además su identidad, extensiones y garantías operacionales. Presentamos
PasskeyTransit v0.2, un harness reproducible para CXF, CXP/HPKE, WebAuthn,
mutaciones y fallos transaccionales. La campaña principal ejecutó
{c1['attempt_count']:,} intentos sobre {c1['credential_count']} credenciales,
{c1['route_count']} rutas y dos repeticiones usando políticas de control y
autenticadores virtuales Chromium. Las {c1['oracle_statuses']['webauthn_assertion']['PASS']:,}
aserciones WebAuthn fueron aceptadas, pero {reassurance['numerator']:,} intentos
({_percent(reassurance['estimate'])}; IC95% por bootstrap de credencial
{_percent(reassurance['ci95'][0])}–{_percent(reassurance['ci95'][1])}) combinaron
login correcto con el fallo de otra propiedad aplicable. La preservación
semántica completa observable fue {_percent(yield_result['estimate'])}
({yield_result['numerator']:,}/{yield_result['denominator']:,}; IC95%
{_percent(yield_result['ci95'][0])}–{_percent(yield_result['ci95'][1])}). Estos
porcentajes caracterizan estímulos sintéticos diseñados, no productos ni
prevalencia real. PRF y preservación positiva de `credBlob` permanecen no
evaluables por límites de la interfaz CDP.

## 1. Introducción

CXF estandariza la representación de credenciales y CXP propone su transporte
protegido. Sin embargo, aceptar un documento e incluso completar una aserción
WebAuthn no demuestra por sí solo que sobrevivan todas las propiedades de una
passkey. Modelamos la credencial como `C=(I,K,F,S)`: identidad, material
criptográfico, funciones observables y garantías operacionales.

La proposición falsable es que una importación aceptada y un login correcto son
insuficientes para establecer preservación semántica completa. No formulamos
afirmaciones de novedad ni sobre implementaciones comerciales no examinadas.

## 2. Método

El protocolo `passkeytransit-semantic-preservation-v1.0` fue congelado antes de
la implementación confirmatoria. El corpus contiene 256 credenciales ES256,
32 en cada uno de ocho estratos: básica, PRF con UV, PRF sin UV, `largeBlob`,
`credBlob`, marcador de pagos, combinación de extensiones y miembro opcional
futuro. Doce rutas cubren migración directa, round trip y multihop.

Cada salto serializa un documento CXF validado y lo transporta mediante HPKE
base X25519/HKDF-SHA256/AES-128-GCM. El navegador importa el resultado en un
autenticador virtual y ejecuta `navigator.credentials.get()`. Un verificador
Python independiente de la ceremonia comprueba desafío, origen, RP-ID hash,
flags UP/UV, firma ES256 y contador cero.

Los oráculos devuelven `PASS`, `FAIL`, `NOT_APPLICABLE` o `NOT_EVALUABLE`.
Separadamente clasificamos estado de ejecución, preservación semántica y
evaluación normativa. Los intervalos se obtienen con bootstrap agrupado por
credencial; las comparaciones de rutas son pareadas por credencial y repetición.

## 3. Implementación del transporte

La implementación HPKE reproduce el vector oficial de RFC 9180. El Working
Draft CXP no define campos para la encapsulación HPKE ni para el challenge
firmado que describe su narrativa, y no concreta completamente el ZIP/JWE.
Usamos una extensión experimental autenticada como AAD y no reclamamos
interoperabilidad CXP normativa completa.

Una segunda implementación, `cryptography 50.0.1`, intercambió ciphertexts
HPKE en ambas direcciones con PasskeyTransit. Un consumidor Node.js independiente
validó el envelope CXF, PKCS#8, SPKI, credential ID y `largeBlob` DEFLATE. El
ensayo híbrido ML-KEM-768+X25519 fue exitoso, pero permanece fuera del perfil
CXP y de los estimandos.
{external_text}

## 4. Resultados

### 4.1. Campaña C1 con navegador

Todos los {c1['attempt_count']:,} intentos fueron importados; identidad,
correspondencia de clave pública, aserción WebAuthn y UV pasaron en todos ellos.
Las dos repeticiones produjeron resultados determinísticos equivalentes.

| Clase semántica | N | Proporción |
|---|---:|---:|
| PASS | {c1['semantic_classes']['PASS']:,} | {_percent(c1['semantic_classes']['PASS']/c1['attempt_count'])} |
| Degradación visible | {c1['semantic_classes']['DEGRADED_VISIBLE']:,} | {_percent(c1['semantic_classes']['DEGRADED_VISIBLE']/c1['attempt_count'])} |
| Degradación silenciosa | {c1['semantic_classes']['DEGRADED_SILENT']:,} | {_percent(c1['semantic_classes']['DEGRADED_SILENT']/c1['attempt_count'])} |
| No evaluable | {c1['semantic_classes']['NOT_EVALUABLE']:,} | {_percent(c1['semantic_classes']['NOT_EVALUABLE']/c1['attempt_count'])} |

La tasa de degradación silenciosa fue {_percent(silent['estimate'])}
({silent['numerator']:,}/{silent['denominator']:,}; IC95%
{_percent(silent['ci95'][0])}–{_percent(silent['ci95'][1])}). `largeBlob` fue
observable en 1.536 casos aplicables: 768 pasaron y 768 fallaron según la ruta
de control. La pérdida en un intermediario persistió al volver a un destino
capaz, produciendo discordancias en comparaciones pareadas con el mismo destino.

### 4.2. Robustez C2

C2 ejecutó {c2['attempt_count']} casos: diez familias sobre ocho estratos. Se
rechazaron 48 documentos inválidos o colisiones. Los 16 casos de key mismatch o
cambio de RP ID fueron importados por el control sintáctico, pero los oráculos
los clasificaron como degradación silenciosa y violación. Los 16 casos con
miembro opcional desconocido o versión menor futura fueron importados sin error
estructural. Las familias se informan separadamente y no se calcula un porcentaje
agrupado.

### 4.3. Fallos y recuperación C3

C3 ejecutó {total_c3} secuencias y {c3['event_count']} eventos. En
{atomic_pass} secuencias ({_percent(atomic_pass/total_c3)}) hubo rollback completo
y el retry convergió a una copia. Las 128 fallas restantes fueron el control
positivo deliberado: `legacy` conservó un provisional en los dos puntos tardíos
y el retry creó un duplicado, haciendo fallar atomicidad e idempotencia.

## 5. Discusión

El experimento demuestra una capacidad del método, no una incidencia del mundo
real: la autenticación funcionó en el 100% de los intentos, incluidos aquellos
en los que los controles descartaron otras propiedades. Por tanto, un test de
login aislado no es un oráculo suficiente para migración semántica.

También observamos dependencia de ruta: un destino final sin pérdidas propias
no puede reconstruir material descartado por un intermediario. La declaración
pre-commit cambia además la clasificación de una misma pérdida de silenciosa a
visible, aun cuando el estado final de la credencial sea idéntico.

## 6. Limitaciones

- Los cuatro perfiles son controles sintéticos, no proveedores comerciales.
- CDP no permite inyectar HMAC/PRF ni `credBlob`; los casos positivos son
  `NOT_EVALUABLE`, nunca `PASS`.
- No ejecutamos Secure Payment Confirmation.
- El binding adicional de CXP es experimental y no resuelve autenticación de
  identidad del exportador en modo HPKE base.
- El ensayo PQC prueba disponibilidad criptográfica, no un perfil CXP-PQC.
- No se permite inferir vulnerabilidades, prevalencia de fallos ni superioridad
  de productos a partir de estos controles.

## 7. Reproducibilidad

Los artefactos raw son JSONL inmutables; los derivados y manifiestos incluyen
hashes SHA-256 del protocolo, resultados, navegador y commit. La campaña C1 se
ejecutó con Edge {results['environment']['browser_version']} y Playwright
{results['environment']['playwright_version']} desde un árbol Git limpio. El
repositorio incluye comandos de una sola operación para tests, C1, C2, C3,
interoperabilidad y regeneración de este análisis.

## 8. Conclusión

PasskeyTransit distingue correctamente compatibilidad sintáctica, autenticación
básica, preservación funcional y recuperación operacional. Los controles
confirman la proposición metodológica: una aserción válida no basta para afirmar
que una passkey migrada conserva todas sus garantías. El paso necesario para
generalizar es ejecutar adaptadores identificados e independientes, manteniendo
los mismos oráculos y límites de afirmación.

## Referencias

1. FIDO Alliance, Credential Exchange Format v1.0 Proposed Standard Errata, 2026,
   https://fidoalliance.org/specifications/.
2. FIDO Alliance, Credential Exchange Protocol v1.0 Working Draft, 2024-10-03,
   https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html.
3. Barnes et al., Hybrid Public Key Encryption, RFC 9180, 2022,
   https://www.rfc-editor.org/rfc/rfc9180.
4. W3C, Web Authentication Level 3 Candidate Recommendation, 2026-05-26,
   https://www.w3.org/TR/webauthn-3/.
5. PyCA, `cryptography` HPKE API documentation,
   https://cryptography.io/en/49.0.0/hazmat/primitives/hpke/.
6. Bitwarden, `credential-exchange` v0.4.0,
   https://github.com/bitwarden/credential-exchange/tree/v0.4.0.
7. Jannett et al., The State of Passkeys, USENIX Security 2026,
   https://www.usenix.org/conference/usenixsecurity26/presentation/jannett.
"""


def run_analysis(
    phase7_summary: Path,
    phase7_manifest: Path,
    c2_summary: Path,
    c2_manifest: Path,
    c3_summary: Path,
    c3_manifest: Path,
    interop_path: Path,
    output_dir: Path,
    external_path: Path | None = None,
    oracle_report_path: Path | None = None,
) -> dict[str, Any]:
    input_paths = {
        "phase7_summary": phase7_summary,
        "phase7_manifest": phase7_manifest,
        "c2_summary": c2_summary,
        "c2_manifest": c2_manifest,
        "c3_summary": c3_summary,
        "c3_manifest": c3_manifest,
        "phase8_interop": interop_path,
    }
    if external_path is not None:
        input_paths["phase11_external_cxf"] = external_path
    if oracle_report_path is not None:
        input_paths["phase12_oracles"] = oracle_report_path
    c1, c1_manifest = _verify(phase7_summary, phase7_manifest)
    c2, c2_manifest = _verify(c2_summary, c2_manifest)
    c3, c3_manifest = _verify(c3_summary, c3_manifest)
    interop = _load(interop_path)
    external = _load(external_path) if external_path is not None else None
    oracle_report = _load(oracle_report_path) if oracle_report_path is not None else None
    if c1.get("mode") != "full" or c1.get("attempt_count") != 6144 or c1.get("repeat_equivalent") is not True:
        raise ValueError("Phase 7 input is not the complete equivalent-repeat C1 run")
    if c3.get("failure_sequence_count") != 960:
        raise ValueError("Phase 6 C3 input is incomplete")
    if interop.get("all_applicable_checks_pass") is not True:
        raise ValueError("Phase 8 interoperability checks did not pass")
    if interop.get("git", {}).get("source_dirty") is not False:
        raise ValueError("Phase 8 interoperability evidence was not generated from a clean source tree")
    if external is not None and external.get("semantic_json_equal") is not True:
        raise ValueError("Phase 11 external CXF round trip did not preserve normalized JSON")
    results = {
        "evidence_class": "reference-control-analysis",
        "c1": c1,
        "c2": c2,
        "c3": c3,
        "interop": interop,
        "external_cxf": external,
        "oracle_capabilities": oracle_report,
        "environment": {
            "browser_version": c1_manifest["browser"]["version"],
            "playwright_version": c1_manifest["playwright_version"],
            "source_commits": sorted({c1_manifest["source_commit"], c2_manifest["source_commit"], c3_manifest["source_commit"]}),
        },
        "supported_claims": [
            "browser assertion alone is insufficient in the designed lossy controls",
            "the harness detects route-dependent, atomicity, and idempotence losses",
            "the RFC 9180 base suite interoperates with cryptography's native implementation",
            "a pinned independent open-source CXF parser preserves the normalized test document",
        ],
        "prohibited_claims": [
            "commercial provider behavior or prevalence",
            "complete normative CXP interoperability",
            "positive PRF or credBlob preservation",
            "a vulnerability or novelty claim",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    results_path = output_dir / "results_v0.2.json"
    manuscript_path = output_dir / "MANUSCRIPT.md"
    results_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    _write_csv(
        output_dir / "table_c1_estimands.csv",
        [
            {"estimand": name, "numerator": value["numerator"], "denominator": value["denominator"], "estimate": value["estimate"], "ci95_low": value["ci95"][0] if value["ci95"] else None, "ci95_high": value["ci95"][1] if value["ci95"] else None}
            for name, value in c1["estimands"].items()
        ],
    )
    _write_csv(
        output_dir / "table_c1_oracles.csv",
        [{"oracle": name, "pass": statuses.get("PASS", 0), "fail": statuses.get("FAIL", 0), "not_applicable": statuses.get("NOT_APPLICABLE", 0), "not_evaluable": statuses.get("NOT_EVALUABLE", 0)} for name, statuses in c1["oracle_statuses"].items()],
    )
    _write_csv(
        output_dir / "table_c2_mutations.csv",
        [{"mutation": name, "attempts": value["attempts"], "execution_statuses": json.dumps(value["execution_statuses"], sort_keys=True), "semantic_classes": json.dumps(value["semantic_classes"], sort_keys=True), "normative_classes": json.dumps(value["normative_classes"], sort_keys=True)} for name, value in c2["mutation_families"].items()],
    )
    _write_csv(
        output_dir / "table_c3_faults.csv",
        [{"destination_failure_point": name, **value} for name, value in c3["by_destination_and_failure_point"].items()],
    )
    manuscript_path.write_text(_manuscript(results), encoding="utf-8")
    managed_outputs = (
        "results_v0.2.json",
        "MANUSCRIPT.md",
        "table_c1_estimands.csv",
        "table_c1_oracles.csv",
        "table_c2_mutations.csv",
        "table_c3_faults.csv",
    )
    output_hashes = {name: _sha(output_dir / name) for name in managed_outputs}
    manifest = {
        "input_hashes": {name: _sha(path) for name, path in input_paths.items()},
        "output_hashes": output_hashes,
        "claim_boundary_enforced": True,
    }
    (output_dir / "analysis_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"results": results, "manifest": manifest}
