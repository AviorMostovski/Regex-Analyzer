#!/usr/bin/python3

import re
import sys
import subprocess
import os
from rich import print

# Welcome prompt with skull ASCII art
def welcome_prompt():
    print("""
[bold green]
        ______
       /      \\
      |  O  O  |
      |    ^   |
      |   ---  |
       \______/
        
         Welcome to Regex Analyzer by [bold cyan]Avior Mostovski[/bold cyan]!
        [bold yellow]Uncover hidden secrets in your files with precision.[/bold yellow]
[/bold green]
""")

# Custom error exit
def err_exit(message):
    print(f"[bold red]{message}[reset]")
    sys.exit(1)

# Check for arguments
if len(sys.argv) != 2:
    err_exit("Usage: python3 regex_analyzer.py <target_file>")

# Target file
TARGET_FILE = sys.argv[1]

if not os.path.isfile(TARGET_FILE):
    err_exit(f"Error: The file '{TARGET_FILE}' does not exist.")

# Compatibility for `strings` command
STRINGS_PARAM = "--all"
if sys.platform in ["win32", "darwin"]:
    STRINGS_PARAM = "-a"

TEMP_FILE = "temp.txt"

# Run `strings` command and handle exceptions
try:
    subprocess.run(
        f"strings {STRINGS_PARAM} \"{TARGET_FILE}\" > {TEMP_FILE}",
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        shell=True,
        check=True
    )
    if sys.platform != "win32":
        subprocess.run(
            f"strings {STRINGS_PARAM} -e l {TARGET_FILE} >> {TEMP_FILE}",
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            shell=True,
            check=True
        )
except subprocess.CalledProcessError as e:
    err_exit(f"Error: Failed to extract strings from the file. Details: {e}")

# Load all strings into memory
try:
    with open(TEMP_FILE, "r") as file:
        all_strings = file.read().splitlines()
except Exception as e:
    err_exit(f"Error: Unable to read temporary file. Details: {e}")
finally:
    if os.path.exists(TEMP_FILE):
        os.remove(TEMP_FILE)

# Legends
INFO_S = f"[bold cyan][[bold green]*[bold cyan]][reset]"
ERROR_S = f"[bold cyan][[bold red]![bold cyan]][reset]"

# Regex dictionary
REGEX_DICT = {
    "Amazon_AWS_Access_Key_ID": r"([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
    "Amazon_AWS_S3_Bucket": r"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
    "Discord_Attachments": r"((media|cdn)\\.)?(discordapp\\.net/attachments|discordapp\\.com/attachments)/.+[a-z]",
    "Discord_BOT_Token": r"((?:N|M|O)[a-zA-Z0-9]{23}\\.[a-zA-Z0-9-_]{6}\\.[a-zA-Z0-9-_]{27})$",
    "Facebook_Secret_Key": r"([f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K]|[f|F][b|B])(.{0,20})?['\"][0-9a-f]{32}",
    "Bitcoin_Wallet_Address": r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$",
    "Firebase": r"[a-z0-9.-]+\\.firebaseio\\.com",
    "GitHub": r"[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"]{1}[0-9a-zA-Z]{35,40}['|\"]{1}",
    "Google_API_Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Heroku_API_Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "IP_Address": r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$",
    "URL": r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!\\*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
    "Monero_Wallet_Address": r"4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}",
    "Mac_Address": r"(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\\.]){2}[0-9A-Fa-f]{4})$",
    "Mailto": r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+",
    "Onion": r"([a-z2-7]{16}|[a-z2-7]{56}).onion",
    "Telegram_BOT_Token": r"\d{9}:[0-9A-Za-z_-]{35}",
}

# Regex scanner

def regex_scanner():
    counter = 0
    print(f"{INFO_S} Analyzing the file for sensitive strings. Please wait...\n")
    for key, pattern in REGEX_DICT.items():
        for line in all_strings:
            match = re.search(pattern, line)
            if match:
                print(f"[bold cyan][[bold green]{key}[bold cyan]] > [reset]{match.group(0)}")
                counter += 1

    if counter == 0:
        print(f"{ERROR_S} No sensitive strings found.")

# Execution zone
if __name__ == "__main__":
    welcome_prompt()
    regex_scanner()
