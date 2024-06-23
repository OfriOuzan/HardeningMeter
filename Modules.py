import subprocess
import shlex
import csv
import os
from tabulate import tabulate

OUTPUT = 'output'


def run_command(command):
    """This function run commands and returns the stdout."""
     shlex_command = shlex.split(command)
    try:
        # Run the command and capture the output in binary mode
        result = subprocess.run(shlex_command, capture_output=True)
        stdout = result.stdout
        stderr = result.stderr

        # Attempt to decode the output using 'utf-8', fallback to 'latin-1' if necessary
        try:
            stdout = stdout.decode('utf-8')
        except UnicodeDecodeError:
            stdout = stdout.decode('latin-1')

        try:
            stderr = stderr.decode('utf-8')
        except UnicodeDecodeError:
            stderr = stderr.decode('latin-1')

        return stdout
    except Exception as e:
        print(f"Error executing command '{command}': {e}")
        return None


def read_file(path):
    """This function returns the content of a read file if exists."""
    content = ''
    if os.path.isfile(path):
        file = open(path, 'r')
        content = file.read()
    return content


def write_to_csv(lines, file_name):
    """This function writes the results to a csv file."""
    if not os.path.isdir(OUTPUT):
        os.mkdir(OUTPUT)
    path = f'{OUTPUT}/{file_name}.csv'
    with open(path, 'w') as f:
        writer = csv.writer(f)
        for line in lines:
            writer.writerow(line)


def count_of_x(sublist):
    return sum('X' in value for value in sublist[2:])


def write_results(lines, show_missing, file_name, csv_format):
    """This function writes the results according to the user's request."""
    if 'Binaries' in file_name and show_missing:
        header = [lines[0]]
        l_sorted = sorted(lines[1:], key=count_of_x, reverse=True)
        missing_lines = [sublist for sublist in l_sorted if any('X' in value for value in sublist[2:])]
        lines = header + missing_lines
    if csv_format:
        write_to_csv(lines, file_name)
    else:
        print(file_name)
        print(tabulate(lines, headers="firstrow"))

