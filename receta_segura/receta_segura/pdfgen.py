"""Generacion del PDF de la receta con reportlab."""
import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

TEAL = colors.HexColor("#0f766e")


def _p(text, style):
    return Paragraph(escape(text or "—").replace("\n", "<br/>"), style)


def build_pdf(record: dict, content_hash: str) -> bytes:
    buf = io.BytesIO()
    # pageCompression=0 -> el texto queda legible dentro del PDF (util para la demostracion)
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=1.8 * cm, bottomMargin=1.8 * cm, pageCompression=0,
                            title=f"Receta médica {record['folio']}", author=record["medico"]["nombre"],
                            subject=f"Folio {record['folio']}")
    ss = getSampleStyleSheet()
    title = ParagraphStyle("t", parent=ss["Title"], textColor=TEAL, fontSize=22, spaceAfter=4)
    h = ParagraphStyle("h", parent=ss["Heading3"], textColor=TEAL, spaceBefore=12, spaceAfter=4)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=10.5, leading=14)
    small = ParagraphStyle("s", parent=ss["BodyText"], fontSize=7.5, leading=10, textColor=colors.HexColor("#475569"))

    m, pa = record["medico"], record["paciente"]
    story = [Paragraph("RECETA MÉDICA", title)]

    head = Table([[_p(f"Dr(a). {m['nombre']}", body), _p(f"Folio: {record['folio']}", body)],
                  [_p(f"Cédula profesional: {m['cedula']}", body), _p(f"Fecha: {record['fecha']}", body)]],
                 colWidths=[10 * cm, 7 * cm])
    head.setStyle(TableStyle([("LINEBELOW", (0, -1), (-1, -1), 1.2, TEAL), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story += [head, Paragraph("Paciente", h),
              _p(f"{pa['nombre']}" + (f"  ·  {pa['edad']} años" if pa["edad"] else ""), body),
              Paragraph("Diagnóstico", h), _p(record["diagnostico"], body),
              Paragraph("Prescripción (Rx)", h)]

    rows = [[_p("Medicamento", body), _p("Dosis", body), _p("Indicaciones", body)]]
    rows += [[_p(x["nombre"], body), _p(x["dosis"], body), _p(x["indicaciones"], body)] for x in record["medicamentos"]]
    t = Table(rows, colWidths=[6 * cm, 3.5 * cm, 7.5 * cm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ccfbf1")),
                           ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t, Paragraph("Observaciones", h), _p(record["observaciones"], body), Spacer(1, 40)]

    story += [t, Paragraph("Observaciones", h), _p(record["observaciones"], body), Spacer(1, 40)]

    doc.build(story)
    return buf.getvalue()
