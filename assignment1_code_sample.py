import json
import os
import pymysql
import requests

# hardcoded credentials stored in plaintext can leaked information.
# if the heckares gets the credentials they will be able get access in the detabase.
# in the OWASP top ten categories this will fall into (A02:2021 – Cryptographic Failures)
# Outbound communication to an external component

with open("config.json") as config_file:
    config = json.load(config_file)
# seperating credetials in a different file for better security management
db_config = {
    'host': config["DB_HOST"],
    'user': config["DB_USER"],
    'password': config["DB_PASSWORD"],
}
# Attackers can exploit this vulnerability to gain unauthorized access to sensitive information, user accounts, or administrative functionalities.
#  Attackers can overwhelm the application by sending unexpected input, causing it to crash or become unresponsive, leading to service disruption for legitimate users.
# In the OWASP top ten categories this will fall into (A01:2021 – Broken Access Control)
# use Input Validation Cheat Sheet 
# preventing malformed data from persisting in the database and triggering malfunction of various downstream components
# source - https://hackerwhite.com/vulnerability101/desktop-application/inadequate-input-validation-vulnerability
def get_user_input():
    user_input = input('Enter your name: ')
    if not user_input.isalpha():
        raise ValueError("Invalid input: Only letters are allowed.")
    return user_input

def send_email(to, subject, body):
    os.system(f'echo {body} | mail -s "{subject}" {to}')

# insecure data transmission or insecure http protocol.
# HTTP protocol transmits unencrypted data which makes it insecure and creates data vulnurebality.
# using uncrypted http protocol might expose sensetive data/ data leckage.
# Using https instead of using http will improve a secure data transmission protocol and increase data integrity.
# in the OWASP top ten categories this will fall into (A02:2021 – Cryptographic Failures) (A04:2021 – Insecure Design)
# source- https://cheatsheetseries.owasp.org/IndexTopTen.html

def get_data():
    url = 'https://insecure-api.com/get-data'
    # If server does not respond within 5 seconds, it will raise a requests.Timeout error
    response = requests.get(url, timeout=5)
    data = response.text
    return data

def save_to_db(data):
    query = f"INSERT INTO mytable (column1, column2) VALUES ('{data}', 'Another Value')"
    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    cursor.execute(query)
    connection.commit()
    cursor.close()
    connection.close()

if __name__ == '__main__':
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)
