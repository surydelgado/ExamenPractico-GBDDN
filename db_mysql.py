import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()


def get_mysql():
    try:
        connection = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST"),
            user=os.getenv("MYSQL_USER"),
            password=os.getenv("MYSQL_PASSWORD"),
            database=os.getenv("MYSQL_DATABASE")
        )
        return connection
    except mysql.connector.Error as err:
        print(f"Error de conexión a MySQL: {err}")
        return None