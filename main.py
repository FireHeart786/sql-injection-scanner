import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

# Set the User-Agent header to avoid being detected as a bot
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36"
}

# Define a function to check if a response contains SQL injection errors
def is_vulnerable(response):
    errors = {
        "mysql": ("You have an error in your SQL syntax", "mysql_fetch_array", "mysql_fetch_assoc", "mysql_num_rows"),
        "mssql": ("Microsoft OLE DB Provider for ODBC Drivers", "Microsoft OLE DB Provider for SQL Server", "Unclosed quotation mark after the character string", "SQL Server error", "Microsoft SQL Native Client", "Error converting data type", "Warning: mssql_query", "Warning: mssql_", "Warning: odbc_"),
        "oracle": ("ORA-01756", "ORA-00936", "ORA-00921", "ORA-00911", "ORA-00933", "ORA-00904")
    }
    for db, error_strings in errors.items():
        for error_string in error_strings:
            if error_string in response.content.decode().lower():
                return True, db
    return False, ""

# Define a function to scan a URL for SQL injection vulnerabilities
def scan_sql_injection(url):
    # Check the base URL for SQL injection vulnerabilities
    for quote in ["'", "\""]:
        test_url = f"{url}{quote}"
        response = requests.get(test_url, headers=headers)
        vulnerable, db = is_vulnerable(response)
        if vulnerable:
            print(f"[+] SQL injection vulnerability detected in {url} using {db} syntax")
            return

    # Check forms on the page for SQL injection vulnerabilities
    response = requests.get(url, headers=headers)
    soup = bs(response.content, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        form_details = {"action": form.attrs.get("action"), "method": form.attrs.get("method"), "inputs": []}
        for input_tag in form.find_all("input"):
            input_details = {"type": input_tag.attrs.get("type"), "name": input_tag.attrs.get("name"), "value": input_tag.attrs.get("value")}
            form_details["inputs"].append(input_details)

        for input_tag in form_details["inputs"]:
            if input_tag["type"] not in ("submit", "checkbox", "radio"):
                # Add a quote character to each input field
                test_input = f"{input_tag['value']}'"
                form_data = {input_tag["name"]: test_input}
                if form_details["method"] == "post":
                    response = requests.post(urljoin(url, form_details["action"]), data=form_data, headers=headers)
                else:
                    response = requests.get(urljoin(url, form_details["action"]), params=form_data, headers=headers)

                vulnerable, db = is_vulnerable(response)
                if vulnerable:
                    print(f"[+] SQL injection vulnerability detected in {urljoin(url, form_details['action'])} using {db} syntax")
                    return

# Example usage: scan a website for SQL injection vulnerabilities
if __name__ == "__main__":
    url = input("Enter URL to scan: ")
    scan_sql_injection(url)
