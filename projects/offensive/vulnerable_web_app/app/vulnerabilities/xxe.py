"""XML External Entity (XXE) - OWASP A05:2021 Security Misconfiguration.

Challenges:
  - Parse XML with external entity expansion enabled
  - Read local files via XXE
  - Perform SSRF via XXE
"""

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from lxml import etree
from pathlib import Path

router = APIRouter()
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)


@router.get("/parse", response_class=HTMLResponse)
async def xxe_parse_page(request: Request) -> HTMLResponse:
    """Render the XML parser page."""
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<user>
  <name>John Doe</name>
  <email>john@example.com</email>
</user>"""
    return templates.TemplateResponse(
        "xxe_parse.html",
        {"request": request, "result": None, "sample_xml": sample_xml},
    )


@router.post("/parse", response_class=HTMLResponse)
async def xxe_parse(
    request: Request,
    xml_content: str = Form(...),
) -> HTMLResponse:
    """VULNERABLE: Parse XML without disabling external entities.

    Allows XXE attacks to read local files:
        <?xml version="1.0"?>
        <!DOCTYPE foo [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <user><name>&xxe;</name></user>
    """
    result = None

    try:
        # VULN: XML parsing with external entities enabled
        parser = etree.XMLParser(
            resolve_entities=True,
            no_network=False,
            dtd_validation=False,
            load_dtd=True,
        )

        root = etree.fromstring(xml_content.encode(), parser)

        # Extract parsed data
        parsed_data = {}
        for child in root:
            parsed_data[child.tag] = child.text or ""

        # Check if XXE payload was used
        flag = None
        xml_lower = xml_content.lower()
        if "<!entity" in xml_lower or "<!doctype" in xml_lower:
            flag = "FLAG{xxe_external_entity_expansion}"

        result = {
            "success": True,
            "parsed": parsed_data,
            "raw_xml": etree.tostring(root, pretty_print=True).decode(),
            "flag": flag,
        }

    except etree.XMLSyntaxError as e:
        result = {
            "success": False,
            "error": f"XML Parsing Error: {e}",
        }
    except Exception as e:
        result = {
            "success": False,
            "error": f"Error: {e}",
        }

    return templates.TemplateResponse(
        "xxe_parse.html",
        {"request": request, "result": result, "sample_xml": xml_content},
    )
