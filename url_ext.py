import re
import base64
from urllib.parse import urlparse, parse_qs, unquote
from bs4 import BeautifulSoup

# ---------------------------------------------------------
# 1. Remove zero‑width characters & homoglyphs
# ---------------------------------------------------------
def clean_unicode(text):
    zero_width = [
        "\u200b", "\u200c", "\u200d", "\u2060",
        "\ufeff", "\u180e", "\u202c", "\u202d"
    ]
    for z in zero_width:
        text = text.replace(z, "")
    return text


# ---------------------------------------------------------
# 2. Decode Microsoft SafeLinks
# ---------------------------------------------------------
def decode_safelink(url):
    if "safelinks.protection.outlook.com" not in url:
        return url
    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if "url" in query:
            return unquote(query["url"][0])
    except:
        pass
    return url


# ---------------------------------------------------------
# 3. Decode Proofpoint URLDefense
# ---------------------------------------------------------
def decode_proofpoint(url):
    if "urldefense.proofpoint.com" not in url:
        return url

    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        if "u" not in query:
            return url

        encoded = query["u"][0]

        # Step 1: Replace Proofpoint dash encoding
        # https-3A__malicious-login.com_auth
        decoded = encoded

        # Replace "-3A" with ":" and "-2F" with "/" etc.
        dash_map = {
            "-3A": ":",
            "-2F": "/",
            "-2E": ".",
            "-3D": "=",
            "-26": "&",
            "-3F": "?",
        }

        for k, v in dash_map.items():
            decoded = decoded.replace(k, v)

        # Step 2: Replace "__" with "//"
        decoded = decoded.replace("__", "//")

        # Step 3: Replace "_" with "/"
        decoded = decoded.replace("_", "/")

        # Step 4: URL-decode any remaining %xx sequences
        decoded = unquote(decoded)

        return decoded

    except Exception:
        return url


# ---------------------------------------------------------
# 4. Decode Barracuda LinkProtect
# ---------------------------------------------------------
def decode_barracuda(url):
    if "linkprotect.cudasvc.com" not in url:
        return url

    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        if "a" in query:
            encoded = query["a"][0]

            # Normalize lowercase encodings
            encoded = encoded.replace("%3a", "%3A").replace("%2f", "%2F")

            return unquote(encoded)
    except:
        pass

    return url


# ---------------------------------------------------------
# 5. Decode Mimecast rewrites
# ---------------------------------------------------------
def decode_mimecast(url):
    if "mimecast.com" not in url:
        return url

    try:
        # Extract encoded block after /s/
        match = re.search(r"/s/([^/?]+)", url)
        if not match:
            return url

        encoded = match.group(1)

        # Fix Base64 padding
        missing = len(encoded) % 4
        if missing:
            encoded += "=" * (4 - missing)

        decoded = base64.urlsafe_b64decode(encoded).decode("utf-8")

        # Mimecast sometimes encodes only the path, not the full URL
        # If decoded doesn't start with http, prepend https://
        if not decoded.startswith("http"):
            decoded = "https://" + decoded

        return decoded

    except Exception:
        return url


# ---------------------------------------------------------
# 6. Decode Base64 URLs
# ---------------------------------------------------------
def decode_base64_url(url):
    try:
        if re.fullmatch(r"[A-Za-z0-9+/=]+", url):
            decoded = base64.b64decode(url).decode("utf-8")
            if decoded.startswith("http"):
                return decoded
    except:
        pass
    return url


# ---------------------------------------------------------
# 7. Decode hex‑encoded URLs
# ---------------------------------------------------------
def decode_hex_url(url):
    try:
        if "\\x" in url:
            decoded = bytes(url, "utf-8").decode("unicode_escape")
            if decoded.startswith("http"):
                return decoded
    except:
        pass
    return url


# ---------------------------------------------------------
# 8. Normalize obfuscations + run all decoders
# ---------------------------------------------------------
def normalize_url(url):
    url = clean_unicode(url)

    # Fix common phishing obfuscations
    url = url.replace("hxxp://", "http://")
    url = url.replace("hxxps://", "https://")
    url = url.replace("h**p://", "http://")
    url = url.replace("h**ps://", "https://")
    url = url.replace("[.]", ".")

    # Run all decoders
    url = decode_safelink(url)
    url = decode_proofpoint(url)
    url = decode_barracuda(url)
    url = decode_mimecast(url)
    url = decode_base64_url(url)
    url = decode_hex_url(url)

    return url


# ---------------------------------------------------------
# 9. Extract URLs from plain text
# ---------------------------------------------------------
def extract_urls_from_text(text):
    text = clean_unicode(text)

    pattern = r'(https?://[^\s<>()"]+|h..p[s]?:\/\/[^\s<>()"]+)'
    urls = re.findall(pattern, text)

    return [normalize_url(u) for u in urls]


# ---------------------------------------------------------
# 10. Extract URLs from HTML
# ---------------------------------------------------------
def extract_urls_from_html(html):
    soup = BeautifulSoup(html, "html.parser")
    urls = []

    # <a href="">
    for link in soup.find_all("a", href=True):
        urls.append(normalize_url(link["href"]))

    # JavaScript redirects
    js_redirects = re.findall(r"window\.location\s*=\s*['\"]([^'\"]+)", html)
    urls.extend([normalize_url(u) for u in js_redirects])

    # Raw URLs inside HTML text
    urls.extend(extract_urls_from_text(soup.get_text()))

    return urls


# ---------------------------------------------------------
# 11. Main extractor
# ---------------------------------------------------------
def extract_urls(email_content):
    urls = []

    urls.extend(extract_urls_from_text(email_content))

    if "<html" in email_content.lower():
        urls.extend(extract_urls_from_html(email_content))

    urls = [normalize_url(u) for u in urls]

    return list(set(urls))

# -------------------------------
# Example usage
# -------------------------------


if __name__ == "__main__":
    choice = input("Enter 1 to paste email text, or 2 to load .eml file: ")

    if choice == "2":
        path = input("Enter path to .eml file: ")
        email_content = load_eml_file(path)
    else:
        print("Paste your email content below. End with CTRL+D (Linux/Mac) or CTRL+Z (Windows):")
        email_content = ""
        try:
            while True:
                email_content += input() + "\n"
        except EOFError:
            pass

    urls = extract_urls(email_content)

    print("\nExtracted URLs:")
    for u in urls:
        print(" -", u)