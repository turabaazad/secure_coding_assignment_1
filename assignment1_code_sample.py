import json
import os
import pymysql
import logging
import requests
import smtplib
from email.mime.text import MIMEText

# ############################ #
#     Finding From Turaba and Yasmin     #
# ############################ #
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

# ############################ #
#     Finding From Turaba      #
# ############################ #
# Attackers can exploit this vulnerability to gain unauthorized access to sensitive information, user accounts, or administrative functionalities.
# Attackers can overwhelm the application by sending unexpected input, causing it to crash or become unresponsive, leading to service disruption for legitimate users.
# In the OWASP top ten categories this will fall into (A03:2021 – Injection)
# use Input Validation Cheat Sheet 
# preventing malformed data from persisting in the database and triggering malfunction of various downstream components
# source - https://hackerwhite.com/vulnerability101/desktop-application/inadequate-input-validation-vulnerability
def get_user_input():
    user_input = input('Enter your name: ')
    if not user_input.isalpha():
        raise ValueError("Invalid input: Only letters are allowed.")
    return user_input

# ############################ #
#     Finding From Pinyi       #
# ############################ #
# It's a bad way to execute the os.system directly using the parameters getting from the users
# Hackers can execute unintended dangerous commands by injecting malicious input, creating security vulnerabilities.
# In the OWASP top ten categories this will fall into (A03:2021 – Injection)
# We could use the built-in library smtplib in Pyhton to send the email
def send_email(to, subject, body):
    # os.system(f'echo {body} | mail -s "{subject}" {to}')
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "system@example.com"
    admin_password = os.getenv("adminpassword")
    msg["To"] = to

    with smtplib.SMTP("smtp.example.com", 587) as server:
        server.starttls()
        server.login("system@example.com", admin_password)
        server.sendmail("system@example.com", [to], msg.as_string())


# ############################ #
#     Finding From Turaba      #
# ############################ #
# insecure data transmission or insecure http protocol.
# HTTP protocol transmits unencrypted data which makes it insecure and creates data vulnurebality.
# using uncrypted http protocol might expose sensetive data/ data leckage.
# Using https instead of using http will improve a secure data transmission protocol and increase data integrity.
# in the OWASP top ten categories this will fall into (A02:2021 – Cryptographic Failures) (A04:2021 – Insecure Design)
# source- https://cheatsheetseries.owasp.org/IndexTopTen.html

# ############################ #
#     Finding From Pinyi       #
# ############################ #
# when we try to get the data from the third-party api, we need to monitor the failures to ensure 
# eveything goes well. If error happens, we could have enough information to debug.
# in the OWASP top ten categories this will fall into (A09:2021 – Security Logging and Monitoring Failures) 
# We could use the logging library to log errors for getting data action
def get_data():
    url = 'https://insecure-api.com/get-data'
    # If server does not respond within 5 seconds, it will raise a requests.Timeout error
    # response = requests.get(url, timeout=5)
    # data = response.text
    # return data
    try:
        response = requests.get(url, timeout=5)
        data = response.text
        return data
    except Exception as e:
        logging.error(f'Error occurred while fetching data from API: {e}')
        return None

# ############################### #
# Finding From Yasmin and Pinyi   #
# ############################### #
# SQL Injection Fix (A03:2021 – Injection) 
# Vulnerability Description:
# The original save_to_db function directly inserts user-provided data into an SQL query string. 
# This is vulnerable to SQL Injection, where an attacker can manipulate the query by injecting malicious SQL code,
# potentially deleting or modifying database records, or even gaining unauthorized access to the database.

# Vulnerable Code Example:
# query = f"INSERT INTO mytable (column1, column2) VALUES ('{data}', 'Another Value')"
# If an attacker provides input like: 'test'); DROP TABLE mytable; --', the query becomes:
# INSERT INTO mytable (column1, column2) VALUES ('test'); DROP TABLE mytable; --', 'Another Value')
# This would lead to the deletion of the entire table, which is a major security risk.

# Fix:
# Use parameterized queries or prepared statements to ensure that user input is treated as data, not as part of the SQL command.
# This approach prevents malicious input from being executed as SQL code, ensuring that the database query is safe from injection attacks.

def save_to_db(data):
    # query = f"INSERT INTO mytable (column1, column2) VALUES ('{data}', 'Another Value')"
    query = f"INSERT INTO mytable (column1, column2) VALUES (%s, 'Another Value')"
    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    # cursor.execute(query)
    cursor.execute(query, (data,))
    connection.commit()
    cursor.close()
    connection.close()

if __name__ == '__main__':
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)
