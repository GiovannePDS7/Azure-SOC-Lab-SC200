#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_eml.py - triagem estática de arquivos .eml (Lab SOC, Fase 2.4)

Extrai cabeçalhos relevantes, resultados de SPF/DKIM/DMARC, cadeia Received,
URLs, domínios, IPs, e-mails e anexos, e aplica heurísticas simples para
apontar sinais de phishing. A decisão final (Benign, Suspicious ou Phishing)
é sempre do analista.

USO
  python parse_eml.py amostra.eml
  python parse_eml.py caso1.eml caso2.eml --format json --out resultado.json
  python parse_eml.py amostra.eml --format md > indicators.md

DEPENDÊNCIAS
  Somente a biblioteca padrão do Python 3.8 ou superior.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import unicodedata
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

MAX_BYTES = 25 * 1024 * 1024  # limite defensivo de tamanho de arquivo

# ---------------------------------------------------------------------------
# Constantes e expressões regulares
# ---------------------------------------------------------------------------
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.com.br", "icloud.com", "proton.me", "protonmail.com",
    "aol.com", "gmx.com", "bol.com.br", "uol.com.br", "terra.com.br",
}
FREEMAIL_LABELS = {"freemail", "webmail"}  # cobre o freemail.example do laboratório

RISKY_EXT = {
    "exe", "scr", "js", "vbs", "bat", "cmd", "lnk", "iso", "img", "hta", "ps1",
    "jar", "html", "htm", "svg", "docm", "xlsm", "pptm",
}
MACRO_EXT = {"docm", "xlsm", "pptm"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "rtf"}

URL_RE = re.compile(r"https?://[^\s<>\"'\\)\]]+", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_IN_TEXT_RE = re.compile(r"\b((?:[a-z0-9\-]+\.)+[a-z]{2,})\b", re.I)

URGENCY_RE = re.compile(
    r"\b(urgente|imediat\w*|hoje as \d+\w*|ate hoje|24 ?h(?:oras)?|bloquead\w*|bloqueio|"
    r"suspens\w*|expira\w*|multa|prazo|urgent|immediately|within 24|suspended|final notice)\b")
PAYMENT_RE = re.compile(
    r"\b(pix|chave pix|dados bancarios|nova conta|conta anterior|conta encerrada|boleto|"
    r"transferencia|bank details|new account|iban|swift)\b")
CREDENTIAL_RE = re.compile(
    r"\b(senha|cpf|cartao|token|codigo de seguranca|password|credentials|"
    r"confirme seus dados|confirm your (?:details|account))\b")
OUT_OF_BAND_RE = re.compile(
    r"(nao ligue|apenas por e-?mail|somente por e-?mail|telefone[^.\n]{0,40}manutenc|"
    r"only (?:by|via) e-?mail)")

SEV_ORDER = {"alta": 0, "media": 1, "baixa": 2, "info": 3}
SEV_LABEL = {"alta": "ALTA ", "media": "MÉDIA", "baixa": "BAIXA", "info": "INFO "}


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------
class Defang:
    """Converte indicadores para formato seguro de publicação."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def dom(self, value: str) -> str:
        return value.replace(".", "[.]") if self.enabled else value

    def ip(self, value: str) -> str:
        return value.replace(".", "[.]") if self.enabled else value

    def email(self, value: str) -> str:
        if not self.enabled or "@" not in value:
            return value
        local, _, domain = value.rpartition("@")
        return f"{local}@{domain.replace('.', '[.]')}"

    def url(self, value: str) -> str:
        if not self.enabled:
            return value
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            return value.replace(".", "[.]")
        scheme = "hxxp" + parsed.scheme[4:] if parsed.scheme.lower().startswith("http") else parsed.scheme
        rest = value[len(parsed.scheme) + 3 + len(parsed.netloc):]
        return f"{scheme}://{parsed.netloc.replace('.', '[.]')}{rest}"


def norm(text: str) -> str:
    """Minúsculas e sem acentos, para comparar palavras-chave."""
    text = unicodedata.normalize("NFKD", text)
    return "".join(c for c in text if not unicodedata.combining(c)).lower()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def domain_of(address: str) -> str:
    return address.rpartition("@")[2].strip(" <>\"'").lower() if "@" in address else ""


def msgid_domain(value: str) -> str:
    match = re.search(r"@([^>\s]+)", value or "")
    return match.group(1).lower() if match else ""


def aligned(a: str, b: str) -> bool:
    """Alinhamento relaxado aproximado (sem a Public Suffix List)."""
    a, b = a.lower(), b.lower()
    return bool(a and b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def skeleton(domain: str) -> str:
    """Reduz homóglifos comuns (rn->m, vv->w, 0->o, 1->l) para comparação."""
    s = domain.lower()
    for src, dst in (("rn", "m"), ("vv", "w")):
        s = s.replace(src, dst)
    return s.translate(str.maketrans({"0": "o", "1": "l"}))


def is_lookalike(candidate: str, reference: str) -> bool:
    if not candidate or not reference or candidate == reference:
        return False
    if skeleton(candidate) == skeleton(reference):
        return True
    return len(candidate) >= 8 and levenshtein(candidate, reference) <= 2


def sld(domain: str) -> str:
    """Primeiro rótulo relevante do domínio (aproximação sem PSL)."""
    labels = domain.lower().split(".")
    if labels and labels[0] == "www":
        labels = labels[1:]
    return labels[0] if labels else ""


def is_freemail(domain: str) -> bool:
    return domain in FREEMAIL_DOMAINS or sld(domain) in FREEMAIL_LABELS


DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def ip_scope(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "inválido"
    if any(ip in net for net in DOC_NETS):
        return "documentação (RFC 5737)"
    return "privado" if ip.is_private else "público"


class HtmlCollector(HTMLParser):
    """Coleta links, imagens, formulários e texto visível sem renderizar nada."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.images, self.forms, self.text = [], [], [], []
        self._a = None
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._a = {"href": a["href"], "text": ""}
        elif tag == "img":
            self.images.append({"src": a.get("src") or "", "width": a.get("width"), "height": a.get("height")})
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append({"name": a.get("name") or "", "type": (a.get("type") or "text").lower()})

    def handle_data(self, data):
        self.text.append(data)
        if self._a is not None:
            self._a["text"] += data

    def handle_endtag(self, tag):
        if tag == "a" and self._a is not None:
            self._a["text"] = self._a["text"].strip()
            self.links.append(self._a)
            self._a = None
        elif tag == "form":
            self._form = None


def collect_html(html: str) -> HtmlCollector:
    collector = HtmlCollector()
    try:
        collector.feed(html)
        collector.close()
    except Exception:  # HTML malformado não pode interromper a triagem
        pass
    return collector


def decode_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def pdf_static_text(data: bytes) -> list[str]:
    """Extrai texto de streams PDF não comprimidos (melhor esforço)."""
    lines = []
    for m in re.finditer(rb"\(((?:\\.|[^\\()])*)\)\s*Tj", data):
        text = re.sub(r"\\([()\\])", r"\1", m.group(1).decode("latin-1")).strip()
        if text:
            lines.append(text)
    return lines


# ---------------------------------------------------------------------------
# Análise
# ---------------------------------------------------------------------------
def parse_received(msg) -> list[dict]:
    hops = []
    for raw in msg.get_all("received", []) or []:
        text = " ".join(str(raw).split())
        from_part = re.split(r"\sby\s", text, maxsplit=1, flags=re.I)[0]
        by = re.search(r"\bby\s+(\S+)", text, re.I)
        proto = re.search(r"\bwith\s+(\S+)", text, re.I)
        frm = re.search(r"\bfrom\s+(\S+)", from_part, re.I)
        stamp = text.rsplit(";", 1)[1].strip() if ";" in text else ""
        ips = []
        for candidate in IPV4_RE.findall(from_part):
            try:
                ipaddress.ip_address(candidate)
                if candidate not in ips:
                    ips.append(candidate)
            except ValueError:
                pass
        hops.append({"de": frm.group(1) if frm else "", "por": by.group(1) if by else "",
                     "protocolo": proto.group(1) if proto else "", "ips": ips, "data": stamp})
    return list(reversed(hops))  # do mais antigo para o mais recente


def parse_auth(msg) -> dict:
    joined = " ".join(" ".join(str(h).split()) for h in (msg.get_all("authentication-results", []) or []))

    def grab(pattern):
        m = re.search(pattern, joined, re.I)
        return m.group(1).strip('"') if m else ""

    sig = " ".join(str(msg.get("dkim-signature", "")).split())
    sig_d = re.search(r"\bd=([^;\s]+)", sig)
    sig_s = re.search(r"\bs=([^;\s]+)", sig)
    return {
        "bruto": joined,
        "spf": {"resultado": grab(r"\bspf=(\w+)"), "dominio": domain_of(grab(r"smtp\.mailfrom=([^\s;]+)")),
                "mailfrom": grab(r"smtp\.mailfrom=([^\s;]+)")},
        "dkim": {"resultado": grab(r"\bdkim=(\w+)"), "dominio": grab(r"header\.d=([^\s;]+)") or (sig_d.group(1) if sig_d else ""),
                 "seletor": grab(r"header\.s=([^\s;]+)") or (sig_s.group(1) if sig_s else "")},
        "dmarc": {"resultado": grab(r"\bdmarc=(\w+)"), "politica": grab(r"\(p=(\w+)"),
                  "dominio": grab(r"header\.from=([^\s;]+)")},
    }


def analyze_attachment(part, df: Defang, url_sink: list) -> dict:
    data = part.get_payload(decode=True) or b""
    name = part.get_filename() or "(sem nome)"
    lower = name.lower()
    parts = lower.split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    prev = parts[-2] if len(parts) > 2 else ""
    head = data[:8]
    if head.startswith(b"%PDF"):
        magic = "PDF"
    elif head.startswith(b"MZ"):
        magic = "executável Windows"
    elif head.startswith(b"PK"):
        magic = "ZIP/OOXML"
    elif data.lstrip()[:15].lower().startswith((b"<html", b"<!doctype", b"<head", b"<body")):
        magic = "HTML"
    else:
        magic = "desconhecido"

    flags = []
    if prev in DOC_EXT and ext in RISKY_EXT:
        flags.append("dupla extensão")
    if ext in MACRO_EXT:
        flags.append("formato com macros")
    if ext in RISKY_EXT and ext not in MACRO_EXT:
        flags.append(f"extensão de risco (.{ext})")
    if ext == "pdf" and magic != "PDF":
        flags.append("conteúdo não corresponde à extensão .pdf")

    info = {"nome": name, "tipo_declarado": part.get_content_type(), "tipo_detectado": magic,
            "tamanho": len(data), "sha256": sha256(data), "flags": flags,
            "marcadores_pdf": {}, "texto_estatico": [], "formularios": []}

    if magic == "PDF":
        markers = {k.decode(): data.count(k) for k in
                   (b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/EmbeddedFile", b"/AA")}
        info["marcadores_pdf"] = {k: v for k, v in markers.items() if v}
        info["texto_estatico"] = pdf_static_text(data)[:25]
        for uri in re.findall(rb"/URI\s*\(([^)]+)\)", data):
            url_sink.append({"url": uri.decode("latin-1"), "origem": f"anexo:{name}", "texto": ""})
        if info["marcadores_pdf"]:
            flags.append("PDF com marcadores ativos: " + ", ".join(info["marcadores_pdf"]))
    elif magic == "HTML":
        html = data.decode("utf-8", errors="replace")
        collector = collect_html(html)
        for form in collector.forms:
            info["formularios"].append(form)
            if form["action"]:
                url_sink.append({"url": form["action"], "origem": f"anexo:{name}:form", "texto": ""})
        for link in collector.links:
            url_sink.append({"url": link["href"], "origem": f"anexo:{name}:href", "texto": link["text"]})
    return info


def analyze(path: Path, df: Defang) -> dict:
    size = path.stat().st_size
    if size > MAX_BYTES:
        raise ValueError(f"arquivo acima do limite de {MAX_BYTES // (1024 * 1024)} MB")
    raw = path.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    # --- cabeçalhos e identidade ------------------------------------------
    h = lambda k: " ".join(str(msg.get(k, "")).split())
    from_pairs = getaddresses([h("from")])
    from_name, from_addr = (from_pairs[0] if from_pairs else ("", ""))
    reply_addrs = [a for _, a in getaddresses([h("reply-to")]) if a]
    return_path = h("return-path").strip("<> ")
    to_addrs = [a for _, a in getaddresses([h("to")]) if a]
    cc_addrs = [a for _, a in getaddresses([h("cc")]) if a]
    from_dom, rp_dom = domain_of(from_addr), domain_of(return_path)
    reply_dom = domain_of(reply_addrs[0]) if reply_addrs else ""
    mid_dom = msgid_domain(h("message-id"))
    irt_doms = {msgid_domain(x) for x in (h("in-reply-to") + " " + h("references")).split() if "@" in x}
    irt_doms.discard("")

    auth = parse_auth(msg)
    received = parse_received(msg)

    # --- corpo, URLs e anexos ---------------------------------------------
    urls, body_text, body_emails, images, forms, links = [], [], set(), [], [], []
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        is_attach = part.get_content_disposition() == "attachment" or bool(part.get_filename())
        ctype = part.get_content_type()
        if is_attach:
            attachments.append(analyze_attachment(part, df, urls))
        elif ctype == "text/plain":
            text = decode_text(part)
            body_text.append(text)
            for m in URL_RE.findall(text):
                urls.append({"url": m.rstrip(".,;"), "origem": "texto", "texto": ""})
        elif ctype == "text/html":
            collector = collect_html(decode_text(part))
            body_text.append(" ".join(collector.text))
            links += collector.links
            images += collector.images
            forms += collector.forms
            for link in collector.links:
                urls.append({"url": link["href"], "origem": "html:href", "texto": link["text"]})
            for img in collector.images:
                if img["src"]:
                    urls.append({"url": img["src"], "origem": "html:img", "texto": ""})
            for form in collector.forms:
                if form["action"]:
                    urls.append({"url": form["action"], "origem": "html:form", "texto": ""})
    plain_all = "\n".join(body_text)
    body_emails = set(EMAIL_RE.findall(plain_all))

    seen, unique_urls = set(), []
    for item in urls:
        key = (item["url"], item["origem"])
        if key not in seen and re.match(r"^https?://", item["url"], re.I):
            seen.add(key)
            parsed = urlparse(item["url"])
            item["dominio"] = (parsed.hostname or "").lower()
            item["esquema"] = parsed.scheme.lower()
            unique_urls.append(item)
    body_urls = [u for u in unique_urls if not u["origem"].startswith("anexo")]

    # --- sinais -----------------------------------------------------------
    findings = []

    def add(sev, ident, detail):
        findings.append({"severidade": sev, "id": ident, "detalhe": detail})

    valid_email = bool(from_addr or h("subject") or received)
    if not valid_email:
        add("media", "arquivo_sem_cabecalhos",
            "Nenhum cabeçalho reconhecível (From, Subject, Received). O arquivo pode não ser um .eml válido.")

    if from_dom and rp_dom and not aligned(from_dom, rp_dom):
        add("media", "from_returnpath_diferentes",
            f"From ({df.dom(from_dom)}) e Return-Path ({df.dom(rp_dom)}) usam domínios diferentes.")
    if from_dom and reply_dom and not aligned(from_dom, reply_dom):
        add("media", "replyto_diferente",
            f"Reply-To ({df.dom(reply_dom)}) difere do From ({df.dom(from_dom)}): respostas saem do domínio do remetente.")
    if reply_dom and is_freemail(reply_dom):
        add("media", "replyto_webmail",
            f"Reply-To em provedor de webmail gratuito ({df.dom(reply_dom)}).")

    spf, dkim, dmarc = auth["spf"], auth["dkim"], auth["dmarc"]
    if spf["resultado"] == "pass" and spf["dominio"] and from_dom and not aligned(spf["dominio"], from_dom):
        add("media", "spf_pass_sem_alinhamento",
            f"SPF passou para {df.dom(spf['dominio'])}, que não se alinha ao From ({df.dom(from_dom)}).")
    if dkim["resultado"] in ("", "none"):
        add("baixa", "dkim_ausente", "Nenhuma assinatura DKIM verificada.")
    if dmarc["resultado"] in ("fail", "softfail", "temperror", "permerror"):
        add("alta", "dmarc_falhou", f"DMARC com resultado '{dmarc['resultado']}' (política p={dmarc['politica'] or '?'}).")
    if all(auth[k]["resultado"] == "pass" for k in ("spf", "dkim", "dmarc")):
        add("info", "autenticacao_aprovada",
            "SPF, DKIM e DMARC passaram. Isso prova quem enviou, não que o domínio seja o esperado.")

    # domínios de referência: conversa citada, e-mails citados e domínios exibidos em links
    refs = set(irt_doms) | {domain_of(e) for e in body_emails}
    shown_domains = set()
    for link in links:
        for m in DOMAIN_IN_TEXT_RE.findall(link["text"]):
            shown_domains.add(m.lower())
    refs |= shown_domains
    refs.discard("")
    cand_labels: dict[str, list] = {}
    for label, cand in (("From", from_dom), ("Return-Path", rp_dom), ("Reply-To", reply_dom)):
        if cand:
            cand_labels.setdefault(cand, []).append(label)
    for cand, labels in cand_labels.items():
        for ref in sorted(refs):
            if is_lookalike(cand, ref):
                add("alta", "dominio_lookalike",
                    f"Domínio usado em {'/'.join(labels)} ({df.dom(cand)}) é muito parecido com {df.dom(ref)} "
                    "(possível homóglifo, ex.: rn no lugar de m).")
            elif ref and not aligned(cand, ref) and len(sld(ref)) >= 5 and sld(ref) in cand:
                add("media", "marca_em_dominio_diferente",
                    f"O domínio {df.dom(cand)} ({'/'.join(labels)}) contém a marca de {df.dom(ref)}, mas não é o mesmo domínio.")
    if re.match(r"^\s*(re|res|enc|fw|fwd)\s*:", h("subject"), re.I) and irt_doms and from_dom and not (irt_doms & {from_dom}):
        add("media", "conversa_sequestrada_simulada",
            "Assunto de resposta com In-Reply-To/References apontando para outro domínio "
            f"({', '.join(df.dom(d) for d in sorted(irt_doms))}). Confirme se a mensagem original existe na caixa do destinatário.")

    for link in links:
        host = (urlparse(link["href"]).hostname or "").lower()
        shown = [d.lower() for d in DOMAIN_IN_TEXT_RE.findall(link["text"])]
        if host and shown and not any(aligned(host, s) for s in shown):
            add("alta", "link_texto_diferente_do_destino",
                f"O link exibe {df.dom(shown[0])}, mas aponta para {df.dom(host)}.")
    for item in body_urls:
        if item["esquema"] == "http" and item["origem"] != "html:img":
            add("baixa", "link_http_sem_tls", f"Link sem TLS: {df.url(item['url'])}")
    for img in images:
        w, hgt = (img.get("width") or ""), (img.get("height") or "")
        if str(w) == "1" and str(hgt) == "1" and img["src"]:
            add("media", "pixel_de_rastreamento",
                f"Imagem 1x1 remota: {df.url(img['src'])}. Confirma abertura e pode identificar a vítima.")

    for att in attachments:
        for flag in att["flags"]:
            sev = "alta" if flag.startswith(("dupla", "PDF com marcadores", "conteúdo não")) else "media"
            add(sev, "anexo_suspeito", f"Anexo '{att['nome']}': {flag}.")
        for form in att["formularios"]:
            kinds = {i["type"] for i in form["inputs"]}
            names = ", ".join(i["name"] for i in form["inputs"] if i["name"]) or "?"
            if "password" in kinds or form["action"]:
                add("alta", "formulario_coleta_credenciais",
                    f"Anexo '{att['nome']}' contém formulário ({form['method'].upper()}) com campos [{names}] "
                    f"enviando para {df.url(form['action']) if form['action'] else '(sem destino)'}.")
        pdf_text = norm(" ".join(att["texto_estatico"]))
        if len(set(m.group(1) for m in PAYMENT_RE.finditer(pdf_text))) >= 2:
            add("media", "anexo_com_dados_bancarios",
                f"O texto estático de '{att['nome']}' traz dados bancários/PIX. O risco está no conteúdo, não no arquivo.")
    for form in forms:
        if "password" in {i["type"] for i in form["inputs"]}:
            add("alta", "formulario_no_corpo", "Formulário com campo de senha no corpo do e-mail.")

    subject_text = norm(h("subject") + "\n" + plain_all)
    urgency = sorted({m.group(1) for m in URGENCY_RE.finditer(subject_text)})
    payment = sorted({m.group(1) for m in PAYMENT_RE.finditer(subject_text)})
    creds = sorted({m.group(1) for m in CREDENTIAL_RE.finditer(subject_text)})
    out_of_band = OUT_OF_BAND_RE.search(subject_text)
    if urgency:
        add("media", "linguagem_de_urgencia", "Termos de urgência/pressão: " + ", ".join(urgency[:8]) + ".")
    if creds:
        add("media", "pedido_de_dados_sensiveis", "Termos de credenciais/dados pessoais: " + ", ".join(creds[:8]) + ".")
    if out_of_band:
        add("alta", "bloqueio_de_validacao_fora_de_banda",
            "Mensagem desencoraja validação por outro canal (ex.: telefone). Valide sempre por um contato já conhecido.")
    if len(payment) >= 2 and (urgency or out_of_band):
        add("alta", "padrao_bec",
            "Pedido de troca de dados de pagamento com pressão de prazo ("
            + ", ".join(payment[:6]) + "). Padrão típico de fraude de fornecedor/BEC; não depende de link nem de malware.")
    if not body_urls:
        add("info", "sem_urls_no_corpo", "Nenhuma URL no corpo. Ferramentas baseadas em reputação de URL não ajudam neste caso.")

    # --- indicadores consolidados -----------------------------------------
    domains: dict[str, set] = {}

    def dom_add(domain, role):
        if domain:
            domains.setdefault(domain.lower(), set()).add(role)

    dom_add(from_dom, "From"); dom_add(rp_dom, "Return-Path"); dom_add(reply_dom, "Reply-To")
    dom_add(mid_dom, "Message-ID"); dom_add(spf["dominio"], "SPF"); dom_add(dkim["dominio"], "DKIM")
    dom_add(domain_of(h("to")), "To")
    for d in irt_doms:
        dom_add(d, "In-Reply-To/References")
    for e in body_emails:
        dom_add(domain_of(e), "e-mail citado no corpo")
    for item in unique_urls:
        dom_add(item["dominio"], "URL " + item["origem"])
    hostlike = lambda v: bool(v) and "." in v and not v.startswith("[") and not IPV4_RE.fullmatch(v.strip("[]()"))
    for hop in received:
        dom_add(hop["de"].strip("()") if hostlike(hop["de"]) else "", "Received (de)")
        dom_add(hop["por"] if hostlike(hop["por"]) else "", "Received (por)")

    ips: dict[str, set] = {}
    for hop in received:
        for ip in hop["ips"]:
            ips.setdefault(ip, set()).add("Received")
    for ip in IPV4_RE.findall(auth["bruto"]):
        ips.setdefault(ip, set()).add("Authentication-Results")

    high = sum(f["severidade"] == "alta" for f in findings)
    med = sum(f["severidade"] == "media" for f in findings)
    if not valid_email:
        hint = "arquivo sem cabeçalhos reconhecíveis; confirme se é um .eml válido"
    elif high >= 2:
        hint = "muitos sinais de severidade alta; forte indício de phishing"
    elif high == 1 or med >= 2:
        hint = "sinais relevantes; tratar como suspeito e validar"
    else:
        hint = "poucos sinais técnicos; avaliar contexto e conteúdo"
    findings.sort(key=lambda f: SEV_ORDER[f["severidade"]])

    D = df.dom
    ids = lambda value: " ".join("<" + df.email(x.strip("<>")) + ">" for x in value.split())
    return {
        "arquivo": {"nome": path.name, "tamanho": size, "sha256": sha256(raw)},
        "cabecalhos": {
            "subject": h("subject"), "date": h("date"), "message_id": ids(h("message-id")),
            "from_nome": from_name, "from": df.email(from_addr), "reply_to": [df.email(a) for a in reply_addrs],
            "return_path": df.email(return_path), "to": [df.email(a) for a in to_addrs], "cc": [df.email(a) for a in cc_addrs],
            "in_reply_to": ids(h("in-reply-to")), "references": ids(h("references")),
            "x_mailer": h("x-mailer"), "importance": h("importance"),
        },
        "dominios_chave": {"from": D(from_dom), "return_path": D(rp_dom), "reply_to": D(reply_dom), "message_id": D(mid_dom)},
        "autenticacao": {
            "spf": {**spf, "dominio": D(spf["dominio"]), "mailfrom": df.email(spf["mailfrom"]),
                    "alinhado_ao_from": aligned(spf["dominio"], from_dom) if spf["dominio"] else None},
            "dkim": {**dkim, "dominio": D(dkim["dominio"]),
                     "alinhado_ao_from": aligned(dkim["dominio"], from_dom) if dkim["dominio"] else None},
            "dmarc": {**dmarc, "dominio": D(dmarc["dominio"])},
        },
        "received": [{**hop, "de": D(hop["de"]), "por": D(hop["por"]), "ips": [df.ip(i) for i in hop["ips"]],
                      "escopo_ips": [ip_scope(i) for i in hop["ips"]]} for hop in received],
        "urls": [{"url": df.url(u["url"]), "dominio": D(u["dominio"]), "origem": u["origem"], "texto_exibido": u["texto"]}
                 for u in unique_urls],
        "dominios": [{"dominio": D(d), "papeis": sorted(r)} for d, r in sorted(domains.items())],
        "ips": [{"ip": df.ip(i), "escopo": ip_scope(i), "origem": sorted(r)} for i, r in sorted(ips.items())],
        "emails": sorted({df.email(a) for a in ([from_addr, return_path] + reply_addrs + to_addrs + cc_addrs + list(body_emails)) if a}),
        "anexos": attachments,
        "sinais": findings,
        "resumo": {"alta": high, "media": med, "baixa": sum(f["severidade"] == "baixa" for f in findings),
                   "info": sum(f["severidade"] == "info" for f in findings), "leitura_heuristica": hint,
                   "aviso": "Heurística de apoio. O veredicto final é do analista."},
    }


# ---------------------------------------------------------------------------
# Saídas
# ---------------------------------------------------------------------------
def render_text(r: dict) -> str:
    L, bar = [], "=" * 72
    c, a = r["cabecalhos"], r["autenticacao"]
    L += [bar, f"parse_eml.py - triagem estática: {r['arquivo']['nome']}", bar,
          f"Tamanho : {r['arquivo']['tamanho']:,} bytes".replace(",", "."),
          f"SHA-256 : {r['arquivo']['sha256']}", "",
          "[CABEÇALHOS]",
          f"  Subject     : {c['subject']}", f"  Date        : {c['date']}", f"  Message-ID  : {c['message_id']}",
          f"  From        : {c['from_nome']} <{c['from']}>", f"  Reply-To    : {', '.join(c['reply_to']) or '-'}",
          f"  Return-Path : {c['return_path'] or '-'}", f"  To / Cc     : {', '.join(c['to']) or '-'} / {', '.join(c['cc']) or '-'}",
          f"  In-Reply-To : {c['in_reply_to'] or '-'}", f"  X-Mailer    : {c['x_mailer'] or '-'}",
          f"  Importance  : {c['importance'] or '-'}", "",
          "[AUTENTICAÇÃO]"]
    spf, dkim, dmarc = a["spf"], a["dkim"], a["dmarc"]
    yn = lambda v: "-" if v is None else ("sim" if v else "NÃO")
    L += [f"  SPF   : {spf['resultado'] or '-'} | domínio {spf['dominio'] or '-'} | alinhado ao From: {yn(spf['alinhado_ao_from'])}",
          f"  DKIM  : {dkim['resultado'] or '-'} | domínio {dkim['dominio'] or '-'} | seletor {dkim['seletor'] or '-'} | alinhado ao From: {yn(dkim['alinhado_ao_from'])}",
          f"  DMARC : {dmarc['resultado'] or '-'} | política p={dmarc['politica'] or '-'} | header.from {dmarc['dominio'] or '-'}", "",
          "[CADEIA RECEIVED] (do mais antigo ao mais recente)"]
    for i, hop in enumerate(r["received"], 1):
        ips = ", ".join(f"{ip} ({sc})" for ip, sc in zip(hop["ips"], hop["escopo_ips"])) or "-"
        L.append(f"  {i}. de {hop['de'] or '?'} -> por {hop['por'] or '?'} | {hop['protocolo'] or '-'} | IPs: {ips} | {hop['data']}")
    L += ["", f"[URLs] ({len(r['urls'])})"]
    L += [f"  - {u['url']}  [{u['origem']}]" + (f"  texto exibido: {u['texto_exibido']}" if u["texto_exibido"] else "") for u in r["urls"]] or ["  (nenhuma)"]
    L += ["", f"[DOMÍNIOS] ({len(r['dominios'])})"] + [f"  - {d['dominio']}  ({'; '.join(d['papeis'])})" for d in r["dominios"]]
    L += ["", f"[IPs] ({len(r['ips'])})"] + ([f"  - {i['ip']}  {i['escopo']}  ({', '.join(i['origem'])})" for i in r["ips"]] or ["  (nenhum)"])
    L += ["", f"[ANEXOS] ({len(r['anexos'])})"]
    for att in r["anexos"]:
        L += [f"  - {att['nome']} | {att['tipo_declarado']} | detectado: {att['tipo_detectado']} | {att['tamanho']} bytes",
              f"    SHA-256: {att['sha256']}"]
        if att["flags"]:
            L.append("    Alertas: " + "; ".join(att["flags"]))
        if att["marcadores_pdf"]:
            L.append(f"    Marcadores PDF: {att['marcadores_pdf']}")
        if att["texto_estatico"]:
            L.append("    Texto estático (PDF): " + " | ".join(att["texto_estatico"][:12]))
        for form in att["formularios"]:
            L.append(f"    Formulário {form['method'].upper()} -> {form['action'] or '-'} | campos: "
                     + ", ".join(f"{i['name'] or '?'}:{i['type']}" for i in form["inputs"]))
    if not r["anexos"]:
        L.append("  (nenhum)")
    L += ["", "[SINAIS]"]
    L += [f"  [{SEV_LABEL[f['severidade']]}] {f['id']}: {f['detalhe']}" for f in r["sinais"]] or ["  (nenhum)"]
    s = r["resumo"]
    L += ["", "[RESUMO]", f"  Sinais: alta={s['alta']} média={s['media']} baixa={s['baixa']} info={s['info']}",
          f"  Leitura heurística: {s['leitura_heuristica']}", f"  {s['aviso']}", ""]
    return "\n".join(L)


def render_md(r: dict) -> str:
    esc = lambda v: str(v).replace("|", "\\|")
    L = [f"# Indicadores - {r['arquivo']['nome']}", "",
         f"- **SHA-256 do .eml:** `{r['arquivo']['sha256']}`",
         f"- **Subject:** {esc(r['cabecalhos']['subject'])}", "",
         "## Domínios", "", "| Domínio | Papéis |", "|---|---|"]
    L += [f"| `{d['dominio']}` | {esc('; '.join(d['papeis']))} |" for d in r["dominios"]]
    L += ["", "## IPs", "", "| IP | Escopo | Origem |", "|---|---|---|"]
    L += [f"| `{i['ip']}` | {i['escopo']} | {', '.join(i['origem'])} |" for i in r["ips"]] or ["| - | - | - |"]
    L += ["", "## URLs", "", "| URL | Origem | Texto exibido |", "|---|---|---|"]
    L += [f"| `{u['url']}` | {u['origem']} | {esc(u['texto_exibido'])} |" for u in r["urls"]] or ["| - | - | - |"]
    L += ["", "## E-mails", ""] + [f"- `{e}`" for e in r["emails"]]
    L += ["", "## Anexos", "", "| Nome | Tipo detectado | SHA-256 | Alertas |", "|---|---|---|---|"]
    L += [f"| `{a['nome']}` | {a['tipo_detectado']} | `{a['sha256']}` | {esc('; '.join(a['flags']) or '-')} |" for a in r["anexos"]] or ["| - | - | - | - |"]
    L += ["", "## Sinais identificados", "", "| Severidade | Sinal | Detalhe |", "|---|---|---|"]
    L += [f"| {f['severidade']} | `{f['id']}` | {esc(f['detalhe'])} |" for f in r["sinais"]]
    L += ["", "> Heurística de apoio gerada por `parse_eml.py`. O veredicto final é do analista.", ""]
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Triagem estática de arquivos .eml (sem executar nenhum conteúdo).")
    ap.add_argument("arquivos", nargs="+", type=Path, help="um ou mais arquivos .eml")
    ap.add_argument("--format", choices=("text", "json", "md"), default="text", help="formato de saída (padrão: text)")
    ap.add_argument("--raw", action="store_true", help="não aplicar defang (somente em ambiente isolado)")
    ap.add_argument("--out", type=Path, help="gravar a saída neste arquivo em vez de usar stdout")
    args = ap.parse_args(argv)

    df = Defang(enabled=not args.raw)
    reports, status = [], 0
    for path in args.arquivos:
        try:
            reports.append(analyze(path, df))
        except (OSError, ValueError) as exc:
            print(f"erro ao analisar {path}: {exc}", file=sys.stderr)
            status = 2
    if not reports:
        return status or 2

    if args.format == "json":
        output = json.dumps(reports if len(reports) > 1 else reports[0], ensure_ascii=False, indent=2)
    elif args.format == "md":
        output = "\n\n".join(render_md(r) for r in reports)
    else:
        output = "\n".join(render_text(r) for r in reports)

    if args.out:
        args.out.write_text(output, encoding="utf-8")
        print(f"saída gravada em {args.out}", file=sys.stderr)
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(output)
    return status


if __name__ == "__main__":
    sys.exit(main())
