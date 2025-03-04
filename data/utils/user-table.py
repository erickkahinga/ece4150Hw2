import sys, os
from env import RDS_DB_HOSTNAME, RDS_DB_USERNAME, RDS_DB_PASSWORD, RDS_DB_NAME
import pymysql.cursors

conn = pymysql.connect(host=RDS_DB_HOSTNAME,
             user=RDS_DB_USERNAME,
             password=RDS_DB_PASSWORD,
             db=RDS_DB_NAME,
             charset='utf8mb4',
             cursorclass=pymysql.cursors.DictCursor)

print("Connected to RDS instance at %s" % (RDS_DB_HOSTNAME,))

cursor = conn.cursor()
cursor.execute("SELECT VERSION()")
row = cursor.fetchone ()
print("Server version:", row['VERSION()'])

with open("sqlcommands.sql") as f:
    commands = f.read()
    commands = commands.split('----')
    print("\nRunning commands specified in sqlcommands.sql.")
    for command in commands:
        try:
            cursor.execute(command)
        except:
            print("Got error while attempting to run commands '%s'" % command)
            raise
    print("Commands executed.")

cursor.close()
conn.close()
