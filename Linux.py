import re
import Modules

REL = 'REL'
ELF_TYPES = {'DYN (Position-Independent Executable file)': 'PIE', 'REL (Relocatable file)': 'REL',
             'DYN (Shared object file)': 'SO', 'EXEC (Executable file)': 'Exec'}
READELF = 'readelf -W'
FORTIFY_PATTERN = r"__\w+_chk"
FORTIFY_PATTERN_GLIBC = r"__\w+_chk@@GLIBC"
ASLR = {0: 'Disabled', 1: 'Partial Enabled'}


def check_conf():
    ibt = 'X'
    kaslr_base = 'X'
    kaslr_memory = 'X'
    kaslr_kstack = 'X'
    kaslr_kstack_default = 'X'
    kernel_info = Modules.run_command('uname -r').split('\n')[0]
    file = f'/boot/config-{kernel_info}'
    lines = Modules.read_file(file)
    if not lines:
        ibt = '-'
        kaslr_base = '-'
        kaslr_memory = '-'
        kaslr_kstack = '-'
        kaslr_kstack_default = '-'
    else:
        lines = lines.split('\n')
        for line in lines:
            if line.startswith('CONFIG_X86_KERNEL_IBT=y'):
                ibt = 'V'
            if line.startswith('CONFIG_RANDOMIZE_BASE=y'):
                kaslr_base = 'V'
            if line.startswith('CONFIG_RANDOMIZE_MEMORY=y'):
                kaslr_memory = 'V'
            if line.startswith('CONFIG_RANDOMIZE_KSTACK_OFFSET=y'):
                kaslr_kstack = 'V'
            if line.startswith('CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y'):
                kaslr_kstack_default = 'V'
    return [kaslr_base, kaslr_memory, kaslr_kstack, kaslr_kstack_default, ibt]


def check_cpuinfo():
    smep = 'X'
    smap ='X'
    pti = 'X'
    lines = Modules.read_file('/proc/cpuinfo').split('\n')
    for line in lines:
        if 'smep' in line:
            smep = 'V'
        if 'smap' in line:
            smap = 'V'
        if 'pti' in line:
            pti = 'V'
    return [smep, smap, pti]


def check_nx():
    """This function returns the NX status if exists."""
    dmesg = 'dmesg'
    lines = Modules.run_command(dmesg).split('\n')
    nx = '-'
    for line in lines:
        if 'NX (Execute Disable) protection' in line:
            nx = line.split(':')[-1]
            break
    return nx


def check_aslr():
    """This function returns the ASLR status if exists."""
    path = '/proc/sys/kernel/randomize_va_space'
    content = int(Modules.read_file(path))
    if not content:
        value = '-'
    elif content in ASLR:
        value = ASLR[content]
    else:
        value = 'Full Enabled'
    return value


def readelf_command(flag, file):
    """This function performs readelf commands."""
    get_program_header_command = f'{READELF} {flag} {file}'
    output = Modules.run_command(get_program_header_command)
    return output


def find_glibc(file):
    """This function finds the libc in strategic locations in the fs if it does not exist in the file's ldd ."""
    ldd_command = f'ldd {file}'
    output = Modules.run_command(ldd_command)
    lines = [line.replace(' ', '') for line in output.split('\n')]
    libc_path = ''
    for line in lines:
        if 'libc.so' in line:
            libc_path = line.split('=>')[1].split('(')[0]
    if not libc_path:
        find_libc = 'find /lib /usr/lib /lib64 /usr/lib64 -name "libc.so.6"'
        libc_path = Modules.run_command(find_libc)
        if len(libc_path.split('\n')) > 1:
            libc_path = libc_path.split('\n')[0]
    return libc_path


def get_glibc_fortify_functions(file):
    """This function gets the functions that has the _chk string in them (fortify functions)."""
    libc_path = find_glibc(file)
    if not libc_path:
        return []
    output = readelf_command('-s --dyn-syms', libc_path)
    libc_fortify_functions = re.findall(FORTIFY_PATTERN_GLIBC, output)
    libc_fortify_functions = [libc_fortify_function.split('@')[0] for libc_fortify_function in libc_fortify_functions]
    return libc_fortify_functions


def notes_section(file):
    """This function reads the notes section of the file and returns the status of Indirect Branch Tracking and Shadow
    Stack."""
    shadow_stack = 'X'
    ibt = 'X'
    notes_section_lines = readelf_command('-n', file)
    for line in notes_section_lines.split('\n'):
        if 'IBT' in line:
            ibt = 'V'
        if 'SHSTK' in line:
            shadow_stack = 'V'
        if ibt == 'V' and shadow_stack == 'V':
            return [shadow_stack, ibt]
    return [shadow_stack, ibt]


def relocation_section(file, elf_type):
    """This function reads the relocation section of the file and returns the status of Stack Canaries, Fortify and
    ASAN."""
    canary = 'X'
    fortify = 'X'
    asan = 'X'
    relocation_lines = readelf_command('-r', file).split('\n')
    dynamic_symbols = readelf_command('-s --dyn-syms', file).split('\n')
    libc_fortify_functions = get_glibc_fortify_functions(file)
    libc_fortify_functions_names = [libc_fortify_function.split('_chk')[0] for libc_fortify_function in
                                    libc_fortify_functions]
    fortified = []
    fortifiable = []
    if 'There are no relocations in this file.' in relocation_lines:
        return ['-', '-', '-']
    for line in dynamic_symbols:
        if '__stack_chk_fail' in line:
            canary = 'V'
        elif '@GLIBC' in line:
            function = [value.split('@')[0] for value in line.split(' ') if '@GLIBC' in value][0]
            fortify_function = re.search(FORTIFY_PATTERN, function)
            if fortify_function:
                fortify_function = fortify_function[0]
                if fortify_function in libc_fortify_functions:
                    fortified.append(fortify_function)
                    fortifiable.append(fortify_function)
            if function in libc_fortify_functions_names:
                fortifiable.append(function)
            elif f'__{function}' in libc_fortify_functions_names:
                fortifiable.append(function)
        elif '__asan_' in line:
            asan = 'V'
    if asan == 'V' or 'REL' in elf_type:
        libc_fortify_asan_functions_names = [libc_fortify_asan_function.split('__')[1] for libc_fortify_asan_function
                                             in libc_fortify_functions_names]
        for line in dynamic_symbols:
            if line:
                name = line.split(' ')[-1]
                if '__stack_chk_fail' not in name and '__asan_' not in name:
                    if name in libc_fortify_asan_functions_names:
                        fortifiable.append(name)
                    elif name in libc_fortify_functions:
                        fortified.append(name)
                        fortifiable.append(name)
    if fortified:
        fortify = 'V'
    if fortifiable:
        fortify_functions = f'{len(set(fortified))}/{len(set(fortifiable))}'
        fortify = f'{fortify} {fortify_functions}'
    if not fortifiable:
        fortify = '-'
    return [canary, fortify, asan]


def dynamic_section(file):
    """This function reads the dynamic section of the file and returns the status of bind."""
    bind_now = 'X'
    dynamic_section_lines = readelf_command('-d', file)
    for line in dynamic_section_lines.split('\n'):
        if 'There is no dynamic section in this file.' in line:
            bind_now = '-'
            break
        elif '(FLAGS)' in line and 'BIND_NOW' in line:
            bind_now = 'V'
    return [bind_now]


def program_header(file):
    """This function reads the program header of the file and returns the status of exec stack and relro."""
    not_stack_exec = 'X'
    relro = 'X'
    program_header_lines = readelf_command('-l', file).split('\n')
    for index, line in enumerate(program_header_lines):
        if 'GNU_STACK' in line and index < len(program_header_lines) - 1:
            next_line = program_header_lines[index + 1]
            if 'RWE' not in next_line:
                not_stack_exec = 'V'
        if 'GNU_RELRO' in line:
            relro = 'V'
    return [relro, not_stack_exec]


def check_position_independent(elf_type):
    """This function returns whether the file is position independent."""
    position_independent = 'X'
    if 'SO' in elf_type or 'PIE' in elf_type:
        position_independent = 'V'
    return position_independent


def elf_file_type(file):
    """This function reads the file header and returns the elf type."""
    output = readelf_command('-h', file)
    lines = [line for line in output.split('\n')]
    for line in lines:
        if 'Type' in line:
            for elf_type in ELF_TYPES:
                if elf_type in line:
                    return ELF_TYPES[elf_type]
    print(f'The {file} file type is not supported')
    return ''


def check_go(file):
    """This function checks if the elf file is go file."""
    output = readelf_command('-n', file)
    lines = [line for line in output.split('\n')]
    is_go = False
    for line in lines:
        if 'Displaying notes found in: .note.go.buildid' in line:
            is_go = True
    return is_go


def get_file_command_output(file):
    """This function returns the file command output of a given elf."""
    file_command = f'file {file}'
    output = Modules.run_command(file_command)
    if f'{file}: ELF' in output:
        return output
    return ''


def check_static(file):
    """This function checks if the elf file belongs to the given type."""
    output = get_file_command_output(file)
    is_static = False
    if f'statically linked' in output:
        is_static = True
    return is_static


def get_elf_files(all_files):
    """This function checks if the file is an elf."""
    elf_files = []
    for file in all_files:
        if get_file_command_output(file):
            elf_files.append(file)
    return elf_files


def hardening_checks(all_files, external, show_missing, system, csv_format):
    """This function creates the hardening summary and write it according to the user's output format."""
    if all_files:
        files = get_elf_files(all_files)
        header = ['Path', 'File Type', 'PIE/PIC', 'RELRO', 'NOT Stack Exec', 'BIND NOW', 'Stack Canary',
                  'Fortify Functions', 'Shadow Stack', 'IBT']
        if external:
            header += 'ASAN'
        lines = [header]
        for file in files:
            elf_type = elf_file_type(file)
            canary, fortify, asan = relocation_section(file, elf_type)
            if elf_type:
                if check_go(file):
                    elf_type = f'{elf_type} (Go)'
                if elf_type == REL:
                    line = [file, elf_type, '-', '-', '-', '-']
                    line += [canary, fortify]
                    line += notes_section(file)
                    if external:
                        line += [asan]
                else:
                    if check_static(file):
                        elf_type = f'Static {elf_type}'
                        line = [file, elf_type, 'X']
                        line += program_header(file)
                        line += ['-', canary, fortify]
                        line += notes_section(file)
                        if external:
                            line += [asan]
                    else:
                        elf_type = f'Dynamic {elf_type}'
                        line = [file, elf_type]
                        line += [check_position_independent(elf_type)]
                        line += program_header(file)
                        line += dynamic_section(file)
                        line += [canary, fortify]
                        line += notes_section(file)
                        if external:
                            line += [asan]
                lines.append(line)
        Modules.write_results(lines, show_missing, 'Binaries', csv_format)
    if system:
        smep, smap, pti = check_cpuinfo()
        lines = [['NX', 'ASLR', 'SMEP', 'SMAP', 'KASLR BASE', 'KASLR MEMORY', 'KASLR KSTACK', 'KASLR KSTACK DEFAULT',
                  'IBT', 'PTI'], [check_nx(), check_aslr(), smep, smap] + check_conf() + [pti]]
        Modules.write_results(lines, show_missing, 'System', csv_format)
