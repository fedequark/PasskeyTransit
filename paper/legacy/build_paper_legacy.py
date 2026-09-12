from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.enum.style import WD_STYLE_TYPE
from pathlib import Path

OUT = Path(r"C:\Users\fedep\Documents\Codex\2026-08-06\ay\paper_migracion_passkeys.docx")

INK = "172A3A"
BLUE = "1F5A7A"
MUTED = "596773"
LIGHT = "EAF1F5"
GRID = "AAB7C2"

def font(run, name="Aptos", size=9.2, bold=None, italic=None, color="000000"):
    run.font.name = name
    run._element.get_or_add_rPr().rFonts.set(qn("w:ascii"), name)
    run._element.get_or_add_rPr().rFonts.set(qn("w:hAnsi"), name)
    run.font.size = Pt(size)
    if bold is not None: run.bold = bold
    if italic is not None: run.italic = italic
    run.font.color.rgb = RGBColor.from_string(color)

def shade(cell, fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = tcPr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd"); tcPr.append(shd)
    shd.set(qn("w:fill"), fill)

def set_cell_margins(cell, top=60, start=80, bottom=60, end=80):
    tc = cell._tc; tcPr = tc.get_or_add_tcPr()
    tcMar = tcPr.first_child_found_in("w:tcMar")
    if tcMar is None:
        tcMar = OxmlElement("w:tcMar"); tcPr.append(tcMar)
    for m, v in (("top",top),("start",start),("bottom",bottom),("end",end)):
        node = tcMar.find(qn(f"w:{m}"))
        if node is None: node=OxmlElement(f"w:{m}"); tcMar.append(node)
        node.set(qn("w:w"), str(v)); node.set(qn("w:type"), "dxa")

def set_table_widths(table, widths):
    table.autofit = False
    tblPr = table._tbl.tblPr
    tblW = tblPr.find(qn("w:tblW"))
    if tblW is None: tblW=OxmlElement("w:tblW"); tblPr.append(tblW)
    tblW.set(qn("w:w"), str(sum(widths))); tblW.set(qn("w:type"), "dxa")
    grid = table._tbl.tblGrid
    for child in list(grid): grid.remove(child)
    for w in widths:
        gc=OxmlElement("w:gridCol"); gc.set(qn("w:w"), str(w)); grid.append(gc)
    for row in table.rows:
        for i, cell in enumerate(row.cells):
            tcW=cell._tc.get_or_add_tcPr().find(qn("w:tcW"))
            if tcW is None: tcW=OxmlElement("w:tcW"); cell._tc.get_or_add_tcPr().append(tcW)
            tcW.set(qn("w:w"),str(widths[i])); tcW.set(qn("w:type"),"dxa")
            set_cell_margins(cell)

def set_repeat_table_header(row):
    trPr = row._tr.get_or_add_trPr(); e=OxmlElement("w:tblHeader"); e.set(qn("w:val"),"true"); trPr.append(e)

def add_table(doc, headers, rows, widths=None):
    t=doc.add_table(rows=1, cols=len(headers)); t.alignment=WD_TABLE_ALIGNMENT.CENTER; t.style="Table Grid"
    for i,h in enumerate(headers):
        c=t.rows[0].cells[i]; shade(c, LIGHT); c.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
        p=c.paragraphs[0]; p.paragraph_format.space_after=Pt(0); r=p.add_run(h); font(r,size=7.6,bold=True,color=INK)
    set_repeat_table_header(t.rows[0])
    for vals in rows:
        cells=t.add_row().cells
        for i,v in enumerate(vals):
            p=cells[i].paragraphs[0]; p.paragraph_format.space_after=Pt(0); p.paragraph_format.line_spacing=1.0
            r=p.add_run(str(v)); font(r,size=7.4)
    if widths: set_table_widths(t,widths)
    doc.add_paragraph().paragraph_format.space_after=Pt(0)
    return t

def add_columns(section, count=2, space=360):
    sectPr=section._sectPr
    cols=sectPr.find(qn("w:cols"))
    if cols is None: cols=OxmlElement("w:cols"); sectPr.append(cols)
    cols.set(qn("w:num"),str(count)); cols.set(qn("w:space"),str(space)); cols.set(qn("w:equalWidth"),"1")

def add_para(doc, text, bold_lead=None, italic=False):
    p=doc.add_paragraph(); p.paragraph_format.space_after=Pt(4); p.paragraph_format.line_spacing=1.05
    p.alignment=WD_ALIGN_PARAGRAPH.JUSTIFY
    if bold_lead and text.startswith(bold_lead):
        r=p.add_run(bold_lead); font(r,bold=True)
        r=p.add_run(text[len(bold_lead):]); font(r)
    else:
        r=p.add_run(text); font(r,italic=italic)
    return p

def heading(doc, text, level=1):
    p=doc.add_paragraph(style=f"Heading {level}"); p.paragraph_format.keep_with_next=True
    r=p.add_run(text); return p

def bullet(doc, text):
    p=doc.add_paragraph(style="List Bullet"); p.paragraph_format.space_after=Pt(2); p.paragraph_format.line_spacing=1.0
    font(p.add_run(text),size=8.8); return p

doc=Document()
sec=doc.sections[0]
sec.page_width=Inches(8.5); sec.page_height=Inches(11)
sec.top_margin=Inches(.7); sec.bottom_margin=Inches(.7); sec.left_margin=Inches(.7); sec.right_margin=Inches(.7)
sec.header_distance=Inches(.3); sec.footer_distance=Inches(.35)

# Academic compact preset, named override from compact_reference_guide.
styles=doc.styles
normal=styles["Normal"]; normal.font.name="Aptos"; normal.font.size=Pt(9.2); normal.font.color.rgb=RGBColor.from_string("000000")
normal.paragraph_format.space_after=Pt(4); normal.paragraph_format.line_spacing=1.05
for lvl,size,before,after in [(1,12,9,3),(2,10.3,7,2),(3,9.4,5,2)]:
    s=styles[f"Heading {lvl}"]; s.font.name="Aptos Display"; s.font.size=Pt(size); s.font.bold=True; s.font.color.rgb=RGBColor.from_string(BLUE)
    s.paragraph_format.space_before=Pt(before); s.paragraph_format.space_after=Pt(after); s.paragraph_format.keep_with_next=True
for sty in ["List Bullet","List Number"]:
    s=styles[sty]; s.font.name="Aptos"; s.font.size=Pt(8.8); s.paragraph_format.left_indent=Inches(.18); s.paragraph_format.first_line_indent=Inches(-.12)

# Header/footer
hp=sec.header.paragraphs[0]; hp.alignment=WD_ALIGN_PARAGRAPH.RIGHT
font(hp.add_run("INVESTIGACIÓN HIPOTÉTICA · MIGRACIÓN DE PASSKEYS"),size=7.5,bold=True,color=MUTED)
fp=sec.footer.paragraphs[0]; fp.alignment=WD_ALIGN_PARAGRAPH.CENTER
font(fp.add_run("Borrador académico · resultados simulados"),size=7.2,color=MUTED)

# Title block, one column.
p=doc.add_paragraph(); p.alignment=WD_ALIGN_PARAGRAPH.CENTER; p.paragraph_format.space_before=Pt(22); p.paragraph_format.space_after=Pt(8)
font(p.add_run("La misma clave, distintas garantías"),name="Aptos Display",size=22,bold=True,color=INK)
p=doc.add_paragraph(); p.alignment=WD_ALIGN_PARAGRAPH.CENTER; p.paragraph_format.space_after=Pt(13)
font(p.add_run("Preservación de propiedades de seguridad en la migración de passkeys"),name="Aptos Display",size=13.5,bold=True,color=BLUE)
p=doc.add_paragraph(); p.alignment=WD_ALIGN_PARAGRAPH.CENTER; p.paragraph_format.space_after=Pt(14)
font(p.add_run("[Nombre del autor] · [Afiliación] · [correo electrónico]"),size=9,color=MUTED)

p=doc.add_paragraph(); p.paragraph_format.space_after=Pt(8)
r=p.add_run("NOTA DE ALCANCE. "); font(r,size=8.5,bold=True,color="8A4B00")
r=p.add_run("Este documento es un paper hipotético. Las implementaciones, mediciones y vulnerabilidades son inventadas, aunque técnicamente verosímiles. No deben citarse como hallazgos reales."); font(r,size=8.5,italic=True,color="8A4B00")

heading(doc,"Resumen",1)
add_para(doc,"Credential Exchange Format (CXF) y Credential Exchange Protocol (CXP) buscan permitir la transferencia segura de passkeys y otras credenciales entre credential providers. Aunque estos mecanismos protegen el transporte y estandarizan la representación de las credenciales, no está claro si una passkey conserva sus propiedades funcionales y de seguridad cuando cambia de custodio.")
add_para(doc,"Presentamos el primer estudio sistemático hipotético sobre preservación semántica en la migración de passkeys. Definimos un modelo de equivalencia en tres niveles: identidad criptográfica, equivalencia funcional y equivalencia de seguridad. Desarrollamos PasskeyTransit, un framework de differential testing que genera credenciales sintéticas, ejecuta migraciones y verifica credenciales importadas mediante ceremonias WebAuthn y extensiones como PRF, hmac-secret, largeBlob y credBlob.")
add_para(doc,"Evaluamos cinco implementaciones mediante 1.248 credenciales sintéticas y 18.720 rutas de migración. Aunque el 98,1 % de las credenciales importadas conservó la capacidad básica de autenticación, sólo el 72,6 % preservó todas las propiedades funcionales aplicables. Encontramos 43 divergencias, incluyendo pérdida silenciosa de extensiones, importaciones no idempotentes, degradaciones durante downgrades y resultados PRF inconsistentes después de migraciones múltiples.")
p=doc.add_paragraph(); p.paragraph_format.space_after=Pt(8)
font(p.add_run("Palabras clave: "),size=8.5,bold=True,color=INK); font(p.add_run("passkeys, WebAuthn, CXF, CXP, credential providers, differential testing, interoperabilidad."),size=8.5,italic=True)

# Continuous section and two columns.
body=doc.add_section(WD_SECTION.CONTINUOUS); body.top_margin=Inches(.7); body.bottom_margin=Inches(.7); body.left_margin=Inches(.7); body.right_margin=Inches(.7)
add_columns(body,2,360)

heading(doc,"1. Introducción",1)
add_para(doc,"Las passkeys utilizan criptografía de clave pública para reemplazar contraseñas y proporcionar autenticación resistente al phishing. En WebAuthn, el relying party almacena una clave pública mientras la clave privada permanece bajo el control de un authenticator o credential provider.")
add_para(doc,"La expansión de passkeys sincronizadas introdujo un problema de portabilidad. Una persona que cambia de password manager o ecosistema necesita transferir sus credenciales sin exportar claves privadas mediante archivos de texto inseguros y sin registrar manualmente una passkey nueva en cada servicio.")
add_para(doc,"FIDO Alliance desarrolló CXF, que define la representación de credenciales transferidas, y CXP, que define un protocolo de intercambio protegido entre proveedores. Sin embargo, la confidencialidad del transporte responde sólo una parte del problema. Una passkey importada puede generar firmas válidas y aun así perder resultados PRF, blobs asociados, soporte para pagos, restricciones operacionales o información de custodia.")
add_para(doc,"Pregunta central: ¿qué significa que una passkey siga siendo «la misma» después de cambiar de credential provider? Distinguimos equivalencia criptográfica, funcional y de seguridad.")

heading(doc,"1.1 Contribuciones",2)
for x in ["Modelo de preservación de propiedades para passkeys migradas.","Concepto de credential clone set para representar custodios capaces de utilizar una misma clave.","PasskeyTransit, framework para generar, migrar y ejecutar passkeys sintéticas.","Corpus de 1.248 credenciales con algoritmos, extensiones y condiciones adversariales.","Evaluación de cinco implementaciones mediante rutas directas, round trips y múltiples proveedores.","Reglas para propiedades críticas, atomicidad, idempotencia y consentimiento informado."]:
    bullet(doc,x)

heading(doc,"2. Antecedentes",1)
heading(doc,"2.1 WebAuthn y passkeys",2)
add_para(doc,"Durante el registro WebAuthn, un authenticator crea un par (skC, pkC). El relying party registra pkC; una assertion posterior demuestra posesión de skC mediante una firma sobre authenticatorData y el hash de clientDataJSON.")
add_para(doc,"Además de la clave, una passkey incorpora credential ID, RP ID, user handle, atributos presentables, extensiones WebAuthn/CTAP y propiedades operacionales del proveedor.")
heading(doc,"2.2 Credential Exchange Format",2)
add_para(doc,"CXF representa una passkey mediante credentialId, rpId, username, userDisplayName, userHandle, una clave privada PKCS#8 y extensiones FIDO2 opcionales. La clave debe producir la misma clave pública registrada originalmente. CXF contempla PRF/hmac-secret, credBlob, largeBlob y Secure Payment Confirmation.")
add_para(doc,"La especificación excluye de la exportación passkeys cuyo signature counter sea distinto de cero. Los importadores deben establecerlo en cero y no incrementarlo, una decisión compatible con credenciales sincronizadas pero insuficiente para detectar copias.")
heading(doc,"2.3 Credential Exchange Protocol",2)
add_para(doc,"CXP permite que un importador solicite credenciales indicando versión, algoritmos HPKE, formato de archivo, modo de respuesta, identidad declarada, tipos de credenciales y extensiones conocidas. El exportador construye una respuesta cifrada. El protocolo protege el intercambio, pero no cubre completamente amenazas introducidas por los propios proveedores ni la destrucción posterior de copias.")
heading(doc,"2.4 Conjunto de clones",2)
add_para(doc,"Definimos CloneSet(C,t) como el conjunto de custodios capaces de producir una assertion válida para C en el instante t. Una migración A→B puede transformar {A} en {A,B}; por tanto, salvo eliminación o rotación, amplía el conjunto de entidades capaces de utilizar la credencial.")

heading(doc,"3. Modelo de preservación",1)
add_para(doc,"Representamos una passkey como C=(I,K,F,S), donde I contiene identidad y binding, K material criptográfico, F capacidades funcionales y S propiedades operacionales y de seguridad. Una migración M produce C'=M(C,A,B).")
heading(doc,"3.1 Equivalencia criptográfica",2)
add_para(doc,"C y C' son criptográficamente equivalentes cuando preservan clave pública, credential ID, RP ID y user handle, y una assertion producida por C' es aceptada por el registro original.")
heading(doc,"3.2 Equivalencia funcional",2)
add_para(doc,"Existe equivalencia funcional cuando, además de la identidad criptográfica, toda operación soportada por ambos proveedores produce resultados equivalentes. Para PRF exigimos PRF(C,s)=PRF(C',s) para cada salt de prueba; para blobs exigimos igualdad exacta.")
heading(doc,"3.3 Equivalencia de seguridad",2)
add_para(doc,"Existe equivalencia de seguridad cuando se conserva la funcionalidad, no aparecen custodios no autorizados, las degradaciones se comunican, las restricciones críticas se respetan, la operación es atómica o recuperable y los retries no crean estados ambiguos.")
heading(doc,"3.4 Clases de degradación",2)
add_table(doc,["Clase","Definición"],[("Explícita","Informada y aceptada por el usuario."),("Silenciosa","La importación finaliza sin indicar la pérdida."),("Funcional","Desaparece una capacidad de la credencial."),("Operacional","Cambia custodia, recuperación o exportabilidad."),("Crítica","Puede permitir uso indebido o pérdida irreversible."),("Transitoria/Persistente","Existe sólo durante el flujo o permanece después.")],[1150,3570])

heading(doc,"4. Preguntas de investigación",1)
for q in ["RQ1. ¿Con qué frecuencia se preserva la identidad criptográfica?","RQ2. ¿Qué propiedades funcionales se pierden en rutas directas y de múltiples saltos?","RQ3. ¿Cómo se manejan extensiones desconocidas, downgrades, duplicados y fallos parciales?","RQ4. ¿Puede el usuario o el relying party observar la evolución del conjunto de custodios?"]:
    bullet(doc,q)

heading(doc,"5. PasskeyTransit",1)
heading(doc,"5.1 Arquitectura",2)
add_para(doc,"PasskeyTransit combina un generador de credenciales, un relying party local, adaptadores de proveedores, un mutador estructural y semántico, y oráculos independientes. El ground truth almacena claves, IDs, resultados PRF, blobs y propiedades esperadas.")
heading(doc,"5.2 Proveedores",2)
add_table(doc,["Proveedor","Perfil"],[("P1","Referencia estricta; rechaza degradaciones críticas."),("P2","Referencia permisiva; conserva lo que puede."),("P3","Legacy; sólo identidad básica."),("P4","Prototipo independiente en Rust."),("P5","Prototipo integrado con una API de plataforma.")],[900,3820])
heading(doc,"5.3 Mutaciones y oráculos",2)
add_para(doc,"El mutador elimina, duplica o altera campos; trunca base64url y PKCS#8; cambia RP IDs; introduce extensiones desconocidas, versiones futuras y estructuras profundas. Los oráculos verifican conformidad, correspondencia de claves, assertions WebAuthn, equivalencia de extensiones y divergencia semántica.")
heading(doc,"5.4 Rutas",2)
add_para(doc,"Ejecutamos rutas A→B, A→B→A, A→B→C y A→B→C→A. Repetimos importaciones idénticas para evaluar idempotencia y modificamos metadata entre reintentos.")

heading(doc,"6. Metodología experimental",1)
heading(doc,"6.1 Corpus",2)
add_table(doc,["Categoría","N"],[("Básicas ES256",240),("PRF",208),("hmac-secret",160),("largeBlob",160),("credBlob",160),("Payments",80),("Múltiples extensiones",120),("Extensiones desconocidas",120),("Total",1248)],[3340,1380])
add_para(doc,"El corpus varía credential IDs, RP IDs, user handles, nombres, tamaños, duplicados y campos opcionales. Todas las credenciales son sintéticas y reproducibles a partir de semillas.")
heading(doc,"6.2 Ejecuciones y fallos",2)
add_para(doc,"Ejecutamos 18.720 rutas: 6.240 migraciones directas, 6.240 round trips y 6.240 rutas de tres o más proveedores. Inyectamos fallos después de la aprobación, creación del payload, descifrado, primera persistencia y antes del commit.")
heading(doc,"6.3 Clasificación",2)
add_para(doc,"Cada divergencia fue clasificada como permitida, ambigua, degradación visible, degradación silenciosa, violación normativa o violación de seguridad. El acuerdo interevaluador hipotético fue κ=0,84.")

heading(doc,"7. Resultados",1)
heading(doc,"7.1 Preservación criptográfica",2)
add_para(doc,"El 98,1 % de las credenciales importadas conservó la identidad criptográfica completa. En 61 casos el importador aceptó el documento, pero la credencial resultante no produjo una assertion válida.")
add_table(doc,["Resultado","%"],[("Identidad preservada","98,1"),("Rechazo correcto","1,2"),("Importada, no autenticable","0,5"),("Asociación incorrecta","0,2")],[3200,1520])
add_para(doc,"Las causas fueron clave no persistida (22), normalización incorrecta del credential ID (17), asociación a RP ID incorrecto (8) y reemplazo ambiguo (14). Los casos de RP ID incorrecto aparecieron sólo con inputs mutados inválidos.")
heading(doc,"7.2 Preservación funcional",2)
add_para(doc,"Sólo el 72,6 % mantuvo todas las propiedades funcionales aplicables. Probar únicamente un login posterior no detectó la mayoría de degradaciones.")
add_table(doc,["Propiedad","Preservación"],[("Autenticación básica","98,1 %"),("User verification","96,8 %"),("PRF","81,4 %"),("hmac-secret","79,7 %"),("credBlob","89,1 %"),("largeBlob","83,6 %"),("Payments","68,3 %")],[3000,1720])
add_para(doc,"En migraciones directas compatibles, PRF se conservó en el 96,9 %. En rutas de tres proveedores descendió al 81,4 %. El proveedor legacy ignoró material PRF; al reexportar, la pérdida resultó irreversible.")
add_table(doc,["Ruta","Preservación total"],[("A→B","88,7 %"),("A→B→A","84,2 %"),("A→B→C","76,9 %"),("A→B→C→A","69,8 %")],[2700,2020])
heading(doc,"7.3 Extensiones, downgrade e idempotencia",2)
add_para(doc,"De 2.400 casos con extensiones desconocidas, el 31 % fue preservado como datos opacos, el 27 % rechazado y el 42 % descartado. Sólo el 18 % de los descartes produjo una advertencia visible.")
add_para(doc,"El 14,8 % de los downgrades aceptados perdió alguna propiedad funcional; en el 9,3 % la pérdida fue silenciosa. Dos implementaciones deduplicaron correctamente, una actualizó metadata, una creó duplicados visibles y otra dependió del orden.")
heading(doc,"7.4 Fallos parciales",2)
add_table(doc,["Resultado","%"],[("Atómica","74,1"),("Parcial recuperable","18,6"),("Duplicados tras retry","5,9"),("Limpieza manual","1,4")],[3100,1620])
add_para(doc,"No observamos claves sin cifrar en filesystem, pero dos implementaciones registraron credential IDs y RP IDs completos en logs de diagnóstico.")
heading(doc,"7.5 Evolución del clone set",2)
add_para(doc,"Después de migrar, el proveedor de origen siguió autenticando en el 100 % de los casos; el destino, en el 98,1 %. Eliminar en un proveedor no afectó al otro, y restaurar un backup del origen recuperó copias eliminadas. Operacionalmente, la migración se comportó como clonación, no como transferencia exclusiva.")
heading(doc,"7.6 Resumen",2)
add_table(doc,["Categoría","N"],[("Pérdida silenciosa de extensiones",14),("Importación no idempotente",8),("Downgrade ambiguo",7),("PRF inconsistente",5),("Fallos parciales",4),("Metadata sensible en logs",3),("Confusión entre cuentas",2),("Total",43)],[3600,1120])

heading(doc,"8. Casos representativos",1)
heading(doc,"8.1 Login correcto, PRF incorrecto",2)
add_para(doc,"Una passkey conservó la firma WebAuthn, pero después de pasar por P3 y P4 produjo un resultado PRF diferente para el mismo salt. Una aplicación que usara PRF para cifrado perdería acceso a sus datos aunque el login siguiera funcionando.")
heading(doc,"8.2 Extensión futura descartada",2)
add_para(doc,"P2 omitió una extensión desconocida y reexportó una passkey sintácticamente válida sin ella. En P1→P2→P1, origen y destino final soportaban la propiedad, pero el intermediario destruyó la información.")
heading(doc,"8.3 Retry con duplicados",2)
add_para(doc,"P5 persistió la credencial y falló antes del acknowledgement. El retry creó otra entrada con la misma clave y credential ID, pero diferente item ID interno, impidiendo al usuario identificar el resultado original.")
heading(doc,"8.4 Confusión visual",2)
add_para(doc,"Dos credenciales con nombres Unicode visualmente similares fueron agrupadas pese a tener user handles distintos. WebAuthn permaneció seguro, pero la UI dificultó seleccionar la cuenta correcta.")

heading(doc,"9. Discusión",1)
heading(doc,"9.1 Misma clave no implica misma garantía",2)
add_para(doc,"La equivalencia criptográfica no implica equivalencia funcional, y ésta tampoco implica equivalencia de seguridad. Un importador puede preservar la clave y al mismo tiempo perder extensiones, ampliar custodios, degradar recuperación o crear estados ambiguos.")
heading(doc,"9.2 Criticidad de extensiones",2)
add_table(doc,["Clase","Respuesta recomendada"],[("Informativa","Puede descartarse."),("Funcional","Advertir antes de descartar."),("Disponibilidad crítica","Rechazar o requerir aceptación."),("Seguridad crítica","Abortar migración."),("Identidad crítica","No transformar.")],[1800,2920])
heading(doc,"9.3 Manifest de propiedades",2)
add_para(doc,"Proponemos que el exportador declare propiedades requeridas y opcionales, semántica de custodia y política de downgrade; el importador respondería qué preservó, descartó o no puede verificar. El usuario aprobaría la diferencia antes del commit.")
heading(doc,"9.4 Atomicidad",2)
add_para(doc,"La secuencia recomendada es prepare → validate all → persist atomically → verify usability → commit. Cuando no sea posible, el resultado debe reportarse por credencial como imported, rejected, degraded, rolled-back o unknown.")
heading(doc,"9.5 Migración frente a rotación",2)
add_para(doc,"Copiar la misma clave evita cambios en los relying parties, pero conserva el riesgo de copias previas. Una alternativa es autenticar con la credencial importada, registrar una nueva passkey, verificarla y revocar la antigua: una rotación asistida con una frontera de custodia más clara.")

heading(doc,"10. Recomendaciones",1)
heading(doc,"10.1 Para CXF/CXP",2)
for x in ["Definir semántica explícita de copy, transfer y backup.","Permitir que las extensiones declaren criticidad.","Añadir un manifest de propiedades requeridas.","Prohibir degradaciones silenciosas de propiedades críticas.","Definir idempotency keys, resultados parciales y reglas de downgrade.","Vincular el consentimiento con el conjunto exacto exportado.","Emitir un receipt verificable de migración y custodia."]:
    bullet(doc,x)
heading(doc,"10.2 Para credential providers",2)
for x in ["Verificar la clave antes de persistir y ejecutar una prueba WebAuthn posterior.","Verificar PRF y extensiones cuando sea posible.","Informar propiedades no soportadas y hacer la importación idempotente.","Evitar logs con RP IDs, credential IDs o secretos.","Diferenciar copy de transfer y mostrar si puede reexportarse."]:
    bullet(doc,x)
heading(doc,"10.3 Para relying parties",2)
for x in ["Permitir múltiples passkeys y ofrecer revocación clara.","Mostrar fecha de último uso y facilitar rotación.","No depender de signature counters para passkeys sincronizadas.","Adoptar señales de gestión cuando estén disponibles."]:
    bullet(doc,x)

heading(doc,"11. Limitaciones",1)
add_para(doc,"El estudio evalúa sólo cinco implementaciones y utiliza credenciales sintéticas. Algunas propiedades de custodia no son observables: no podemos demostrar que un proveedor eliminó todas sus copias o backups. CXF/CXP continúan evolucionando y no realizamos un estudio formal con participantes. Sobre todo, los resultados cuantitativos de este borrador son ficticios y sólo ilustran cómo podría presentarse una evaluación real.")

heading(doc,"12. Consideraciones éticas",1)
add_para(doc,"Las pruebas reales deberían usar únicamente cuentas controladas, dispositivos propios y entornos autorizados. Los defectos deben comunicarse mediante responsible disclosure. Los artifacts públicos deberían incluir semillas y generadores, no claves privadas de pruebas reales.")

heading(doc,"13. Trabajo futuro",1)
for x in ["Análisis formal de CXP y vinculación entre consentimiento, importador y payload.","Privacidad estructural frente a orchestrators.","Migración asistida por rotación en relying parties.","Receipts verificables de custodia y degradación.","Estudios de usabilidad sobre copy, transfer, backup y revocación."]:
    bullet(doc,x)

heading(doc,"14. Conclusión",1)
add_para(doc,"La migración de passkeys no es sólo un problema de transporte seguro. Una credencial puede conservar clave, credential ID, RP ID y capacidad de autenticarse, pero perder funcionalidades o cambiar sus garantías operacionales.")
add_para(doc,"La propiedad relevante es que las propiedades requeridas de C estén incluidas entre las propiedades preservadas por M(C). La interoperabilidad sintáctica debe complementarse con mecanismos que hagan explícitas las propiedades preservadas, degradadas y no verificables.")
add_para(doc,"Migrar de forma segura consiste en preservar —o renegociar conscientemente— las garantías asociadas a la clave.")

heading(doc,"Referencias",1)
refs=[
"[1] FIDO Alliance. Credential Exchange Specifications. https://fidoalliance.org/download-credential-exchange-specifications/",
"[2] Apple. What’s New in Passkeys. WWDC 2025. https://developer.apple.com/videos/play/wwdc2025/279/",
"[3] FIDO Alliance. Credential Exchange Format 1.0. https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html",
"[4] FIDO Alliance. Credential Exchange Protocol. https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html",
"[5] W3C. Web Authentication: An API for Accessing Public Key Credentials, Level 3. https://www.w3.org/TR/webauthn-3/",
"[6] IETF. RFC 9180: Hybrid Public Key Encryption. https://www.rfc-editor.org/rfc/rfc9180",
"[7] Apple. ASCredentialImportManager. https://developer.apple.com/documentation/authenticationservices/ascredentialimportmanager",
"[8] Google. Credential Manager. https://developer.android.com/identity/credential-manager"
]
for idx, ref in enumerate(refs):
    if idx == 4:
        bp = doc.add_paragraph()
        bp.paragraph_format.space_after = Pt(0)
        bp.add_run().add_break(WD_BREAK.COLUMN)
    p=doc.add_paragraph(); p.paragraph_format.left_indent=Inches(.14); p.paragraph_format.first_line_indent=Inches(-.14); p.paragraph_format.space_after=Pt(2)
    font(p.add_run(ref),size=7.4)

# Footer page number field in all linked sections.
for section in doc.sections:
    fp=section.footer.paragraphs[0]; fp.alignment=WD_ALIGN_PARAGRAPH.CENTER
    fp.clear(); font(fp.add_run("Borrador académico · resultados simulados · "),size=7.2,color=MUTED)
    run=fp.add_run(); fld=OxmlElement("w:fldSimple"); fld.set(qn("w:instr"),"PAGE"); run._r.addnext(fld)

doc.core_properties.title="La misma clave, distintas garantías"
doc.core_properties.subject="Preservación de propiedades de seguridad en la migración de passkeys"
doc.core_properties.author="[Nombre del autor]"
doc.core_properties.comments="Documento hipotético con resultados simulados"
doc.save(OUT)
print(OUT)
