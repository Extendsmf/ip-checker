import requests
import os
from dotenv import load_dotenv
import sys


if len(sys.argv) < 2:
    print("Ошибка! Вы не передали обязательный аргумент!")
    print("Использование: python checker.py <ip_address>")
    sys.exit(1)

ip_addr = sys.argv[1]


# Загружает данные из файла .env в окружение
load_dotenv()

abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")



def check_abuseipdb(ip, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip_addr,
        'maxAgeInDays': '90'
    }


    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_api_key
    }


    response = requests.get(url, headers=headers, params=querystring, timeout=5)

    if response.status_code == 200:
        res_data = response.json()
        data = res_data.get('data', {}, )
    else:
        print(f"Ошибка: {response.status_code}")
        sys.exit(1)

    return data

def check_virustotal(ip, api_key):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers, timeout=5)

    if response.status_code == 200:
        res_data = response.json()
        data = res_data.get('data', {}, )
    else:
        print(f"Ошибка: {response.status_code}")
        sys.exit(1)

    return data

    


data_abuseipdb = check_abuseipdb(ip_addr, abuseipdb_api_key)

ip = data_abuseipdb.get('ipAddress', 'Не указан')
org = data_abuseipdb.get('isp', 'Не указан')
country = data_abuseipdb.get('countryCode', 'Не указан')
score = data_abuseipdb.get('abuseConfidenceScore', 'Не указан')
in_list = data_abuseipdb.get('isWhitelisted', 'Не указан')
reports = data_abuseipdb.get('totalReports', 'Не указан')

print("--- РЕЗУЛЬТАТ ПРОВЕРКИ AbuseIPDB ---")

print(f"IP: {ip}")
print(f"Организация: {org}")
print(f"Страна: {country}")
print(f"Оценка угрозы (Abuse Score): {score}%")
print(f"В белом списке: {in_list}")
print(f"Всего жалоб: {reports}")
print("-------------------------------------")

data_vt = check_virustotal(ip_addr, virustotal_api_key)

attributes = data_vt.get('attributes', 'Не указан')

owner = attributes.get('as_owner', 'Не указан')
reputation = attributes.get('reputation', 'Не указан')
stats = attributes.get('last_analysis_stats', {})

malicious = stats.get("malicious", 0)
suspicious = stats.get("suspicious", 0)
harmless = stats.get("harmless", 0)

print(f"сколько вендоров считают IP вредоносным: {malicious}")
print(f"сколько вендоров считают IP подозрительным: {suspicious}")
print(f"сколько вендоров считают IP безопасным: {harmless}")
print(f"Владелец: {owner}")
print(f"Репутация: {reputation}")




