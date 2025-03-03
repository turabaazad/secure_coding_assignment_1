import os
import pymysql
import json
import logging
from urllib.request import urlopen

# Securely loading credentials from a config file (config.json) instead of hardcoding them
with open("config.json") as config_file:
    config = json.load(config_file)

db_config = {
    'host': config["DB_HOST"],
    'user': config["DB_USER"],  
    'password': config["DB_PASSWORD"],  
}

# Logging configuration to monitor key actions and detect potential security incidents
logging.basicConfig(filename='app.log', level=logging.INFO)

# Vulnerability 1: Hardcoded Credentials Fix (A02:2021 – Cryptographic Failures) 

# Vulnerability Description:
# Hardcoding credentials in the source code can lead to unintentional exposure of sensitive information.
# Attackers who gain access to the source code may steal the database credentials, leading to unauthorized access.

# Vulnerable Code Example:
# db_config = {
#     'host': 'localhost',
#     'user': 'admin',
#     'password': 'password123'
# }
# Hardcoded credentials in the code are exposed, which is a security risk.

# Fix:
# The credentials are now securely loaded from a configuration file (config.json), preventing them from being exposed in the source code.
# This ensures that sensitive information is not directly accessible from the application code.

def get_user_input():
    """
    Function to capture user input. This input could potentially be malicious if not properly handled.
    """
    user_input = input('Enter your name: ')  # Capture user input
    logging.info(f"User input received: {user_input}")  # Log the input for monitoring purposes
    return user_input

def send_email(to, subject, body):
    """
    Function to send an email. This can be abused if not properly secured.
    """
    os.system(f'echo {body} | mail -s "{subject}" {to}')
    logging.info(f"Email sent to {to} with subject: {subject}")  # Log email activities

def get_data():
    """
    Function to retrieve data from an external API. The request could be a point of attack if not monitored.
    """
    url = 'http://insecure-api.com/get-data'  # Example API that could be insecure
    data = urlopen(url).read().decode()  # Make a request to the insecure API
    logging.info(f"Data retrieved from {url}: {data}")  # Log the retrieved data for monitoring
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
