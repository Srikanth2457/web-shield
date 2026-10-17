import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(start_url, max_pages=20):
    visited = set()          # URLs we've already checked, so we don't loop forever
    to_visit = [start_url]   # URLs waiting to be checked
    site_map = {}            # final result: {url: {"links": [...], "forms": [...]}}

    domain = urlparse(start_url).netloc  # e.g. "127.0.0.1:5001" — used to stay on-site

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue

        try:
            response = requests.get(url, timeout=5)
        except requests.RequestException as e:
            print(f"Could not reach {url}: {e}")
            continue

        visited.add(url)
        soup = BeautifulSoup(response.text, "html.parser")

        # --- find all links on this page ---
        page_links = []
        for a_tag in soup.find_all("a", href=True):
            full_url = urljoin(url, a_tag["href"])
            if urlparse(full_url).netloc == domain:
                page_links.append(full_url)
                if full_url not in visited:
                    to_visit.append(full_url)

        # --- find all forms on this page ---
        page_forms = []
        for form_tag in soup.find_all("form"):
            form_details = {
                "action": urljoin(url, form_tag.get("action", "")),
                "method": form_tag.get("method", "get").lower(),
                "inputs": [
                    {"name": inp.get("name"), "type": inp.get("type", "text")}
                    for inp in form_tag.find_all("input")
                ]
            }
            page_forms.append(form_details)

        site_map[url] = {"links": page_links, "forms": page_forms}
        print(f"Crawled: {url}  ({len(page_links)} links, {len(page_forms)} forms)")

    return site_map


if __name__ == "__main__":
    result = crawl("http://127.0.0.1:5001")
    print("\n--- SITE MAP ---")
    for page, data in result.items():
        print(page, "->", data)