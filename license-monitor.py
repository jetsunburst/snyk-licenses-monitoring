import requests
import csv
from prettytable import PrettyTable

def get_high_severity_licenses(api_url, organization_id, authorization_token):
    full_url = f"{api_url}/v1/org/{organization_id}/licenses?sortBy=license&order=asc"

    headers = {
        'Authorization': f'Token {authorization_token}',
        'Content-Type': 'application/json',
    }

    response = requests.post(full_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        high_severity_licenses = []
        for result in data.get('results', []):
            if result['severity'] == 'high':
                high_severity_licenses.append({
                    'id': result['id'],
                    'severity': result['severity'],
                    'instructions': result['instructions'],
                    'dependencies': result['dependencies'],
                    'projects': result['projects']
                })

        return high_severity_licenses
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def save_to_csv(organization_name, licenses):
    if licenses:
        csv_file_path = f"{organization_name}_high_severity_licenses.csv"

        with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
            fieldnames = ['ID', 'Severity', 'Instructions', 'Dependencies', 'Project Name', 'Project ID']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for vulnerability in licenses:
                for project in vulnerability['projects']:
                    writer.writerow({
                        'ID': vulnerability['id'],
                        'Severity': vulnerability['severity'],
                        'Instructions': vulnerability['instructions'],
                        'Dependencies': vulnerability['dependencies'],
                        'Project Name': project['name'],
                        'Project ID': project['id'],
                    })

def print_table(organizations):
    table = PrettyTable()
    table.field_names = ['Organization Name', 'Organization ID', 'Number of High Severity Licenses']

    for organization_id, organization_name in organizations:
        high_severity_licenses = get_high_severity_licenses(api_url, organization_id, authorization_token)

        if high_severity_licenses is not None:
            table.add_row([organization_name, organization_id, len(high_severity_licenses)])

    print(table)

import time

def print_loading_animation():
    animation = "|/-\\"
    for _ in range(10):
        for char in animation:
            print(f"\rChecking licenses for Organization: {organization_name} (ID: {organization_id}) {char}", end='', flush=True)
            time.sleep(0.1)

if __name__ == "__main__":
    api_url = ""
    authorization_token = ""

    organizations = [
        ("organization_id1", "oganizaiton_name1")
    ]

    all_high_severity_licenses = []

    for organization_id, organization_name in organizations:
        print_loading_animation()   
        high_severity_licenses = get_high_severity_licenses(api_url, organization_id, authorization_token)

        if high_severity_licenses is not None:
            print("\r" + " " * 100, end='')
            save_to_csv(organization_name, high_severity_licenses)
            all_high_severity_licenses.extend(high_severity_licenses)

    print("\nOverall Total number of high severity licenses across all organizations:", len(all_high_severity_licenses))

    print_table(organizations)
