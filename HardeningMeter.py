import argparse
import os
import platform
import Linux


def check_platform(all_files, external, show_missing, system, csv_format):
    """This function checks the platform and execute the hardening checks accordingly."""
    running_os = platform.system()
    if running_os == "Linux":
        Linux.hardening_checks(all_files, external, show_missing, system, csv_format)
    else:
        print(f'We only support Linux at the moment')


def get_all_files(directory):
    """This function gets all the files from the specified directory."""
    all_files = []
    if not os.path.isdir(directory):
        print(f'The following path is not a valid directory: {directory}')
        return all_files
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files


def str_to_bool(value):
    """Custom function to convert string to bool (case-insensitive)."""
    if value.lower() == 'true':
        return True
    elif value.lower() == 'false':
        return False
    else:
        raise argparse.ArgumentTypeError("Boolean value expected (True or False).")


def arguments():
    """This function gets the arguments."""
    parser = argparse.ArgumentParser(description="HardenMeter is a Python tool designed to assess the security "
                                                 "hardening measures implemented in binary files and systems.")
    parser.add_argument('-f', '--file', type=str, nargs='+', default=False,
                        help='Specify the files to check, the argument can contain multiple files separated by spaces.')
    parser.add_argument('-d', '--directory', type=str, default=False,
                        help='Specify the directory you want to scan, the argument get one directory and scans all ELF '
                             'files in it.')
    parser.add_argument('-e', '--external', default=False,
                        help='Specify whether you want to add external checks (False by default).', action='store_true')
    parser.add_argument('-m', '--show_missing', default=False,
                        help='Show only the files that are missing security hardening mechanisms and need extra '
                             'attention.', action='store_true')
    parser.add_argument('-s', '--system', default=False,
                        help='Indicate whether you want to check the system hardening methods (False by default).',
                        action='store_true')
    parser.add_argument('-c', '--csv_format', default=False,
                        help='Specify whether you want to save the results in a csv file; by default, the results are '
                             'output to the screen.', action='store_true')
    return parser.parse_args()


def main():
    """This is the main function, it sets the arguments, get all files and calls the check platform function."""
    args = arguments()
    file = args.file
    directory = args.directory
    external = args.external
    show_missing = args.show_missing
    system = args.system
    csv_format = args.csv_format
    all_files = []
    if directory:
        all_files += get_all_files(directory)
    if file:
        all_files += file
    check_platform(all_files, external, show_missing, system, csv_format)


if __name__ == "__main__":
    main()

