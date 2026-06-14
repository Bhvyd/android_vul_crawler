import re

from bs4 import BeautifulSoup

CVE_REGEX = re.compile(r"CVE-\d{4}-\d+")


def extract_cves_from_html(html: str) -> list[str]:
    soup = BeautifulSoup(html, "lxml")
    text = soup.get_text()
    return sorted(set(CVE_REGEX.findall(text)))
