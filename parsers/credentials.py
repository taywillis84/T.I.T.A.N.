import os
import re
from typing import Dict, List, Optional

CredentialRecord = Dict[str, Optional[str]]


def _read_text(file_path: str) -> str:
    for encoding in ("utf-16", "utf-8", "latin-1"):
        try:
            with open(file_path, "r", encoding=encoding, errors="ignore") as handle:
                return handle.read()
        except UnicodeError:
            continue
    with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read()


def _build_record(
    username: str,
    domain: str,
    secret_type: str,
    secret_value: str,
    source_file: Optional[str],
    source_line: Optional[int],
    source_context: str,
) -> CredentialRecord:
    return {
        "username": username,
        "domain": domain,
        "secret_type": secret_type,
        "secret_value": secret_value,
        "source_file": source_file,
        "source_line": source_line,
        "source_context": source_context,
    }


def parse_mimikatz(content: str, source_file: Optional[str] = None) -> List[CredentialRecord]:
    records: List[CredentialRecord] = []
    sessions = content.split("Authentication Id :")

    for session in sessions:
        user_match = re.search(r"\* Username\s*: (.+)", session)
        domain_match = re.search(r"\* Domain\s*: (.+)", session)
        if not user_match:
            continue

        user = user_match.group(1).strip()
        domain = domain_match.group(1).strip() if domain_match else ""

        if user in {"(null)", ""} or user.endswith("$"):
            continue

        cleartext = None
        for password in re.findall(r"\* Password\s*: (.*)", session):
            cleaned = password.strip()
            if cleaned and cleaned != "(null)":
                cleartext = cleaned
                break

        ntlm_match = re.search(r"\* NTLM\s*: ([A-Fa-f0-9]{32})", session)
        ntlm_hash = ntlm_match.group(1) if ntlm_match else None

        lines = session.splitlines()
        context = next((line.strip() for line in lines if line.strip()), "mimikatz session")
        source_line = None
        if source_file:
            for idx, line in enumerate(content.splitlines(), start=1):
                if user in line and "Username" in line:
                    source_line = idx
                    break

        if cleartext:
            records.append(
                _build_record(user, domain, "password", cleartext, source_file, source_line, context)
            )
        elif ntlm_hash:
            records.append(
                _build_record(user, domain, "hash", ntlm_hash, source_file, source_line, context)
            )

    return records


def parse_secretsdump(content: str, source_file: Optional[str] = None) -> List[CredentialRecord]:
    records: List[CredentialRecord] = []
    pattern = re.compile(r"^([^:\n]+):\d+:([A-Fa-f0-9]{32}):([A-Fa-f0-9]{32}):::")

    for line_number, line in enumerate(content.splitlines(), start=1):
        match = pattern.match(line.strip())
        if not match:
            continue
        username = match.group(1).strip()
        ntlm_hash = match.group(3).strip()
        if not username or username.endswith("$"):
            continue
        records.append(
            _build_record(
                username=username,
                domain="",
                secret_type="hash",
                secret_value=ntlm_hash,
                source_file=source_file,
                source_line=line_number,
                source_context=line.strip(),
            )
        )

    return records


def parse_generic_hash_dump(content: str, source_file: Optional[str] = None) -> List[CredentialRecord]:
    records: List[CredentialRecord] = []
    patterns = [
        re.compile(r"^([^:\\]+)\\([^:\n]+):([A-Fa-f0-9]{32})$"),
        re.compile(r"^([^:\n]+):([A-Fa-f0-9]{32})$"),
    ]

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        domain = ""
        username = ""
        hash_value = ""

        domain_user_match = patterns[0].match(line)
        user_hash_match = patterns[1].match(line)

        if domain_user_match:
            domain = domain_user_match.group(1).strip()
            username = domain_user_match.group(2).strip()
            hash_value = domain_user_match.group(3).strip()
        elif user_hash_match:
            username = user_hash_match.group(1).strip()
            hash_value = user_hash_match.group(2).strip()
        else:
            continue

        if username.endswith("$"):
            continue

        records.append(
            _build_record(
                username=username,
                domain=domain,
                secret_type="hash",
                secret_value=hash_value,
                source_file=source_file,
                source_line=line_number,
                source_context=line,
            )
        )

    return records


def parse_credential_file(file_path: str, format_hint: Optional[str] = None) -> List[CredentialRecord]:
    content = _read_text(file_path)
    hint = (format_hint or "").strip().lower()

    if hint == "mimikatz":
        return parse_mimikatz(content, source_file=file_path)
    if hint == "secretsdump":
        return parse_secretsdump(content, source_file=file_path)
    if hint in {"generic", "hash", "hashdump"}:
        return parse_generic_hash_dump(content, source_file=file_path)

    lowered = content.lower()
    basename = os.path.basename(file_path).lower()

    if "authentication id" in lowered or "* username" in lowered:
        return parse_mimikatz(content, source_file=file_path)
    if ":::" in content or "secretsdump" in basename:
        return parse_secretsdump(content, source_file=file_path)
    return parse_generic_hash_dump(content, source_file=file_path)
