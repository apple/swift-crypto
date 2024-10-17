#!/usr/bin/env python3
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2019-2022 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

import os
import subprocess


# OS_ARCH_COMBOS maps from OS and platform to the OpenSSL assembly "style" for
# that platform and the extension used by asm files.
OS_ARCH_COMBOS = [
    ('ios', 'arm', 'ios32', [], 'S'),
    ('ios', 'aarch64', 'ios64', [], 'S'),
    ('linux', 'arm', 'linux32', [], 'S'),
    ('linux', 'aarch64', 'linux64', [], 'S'),
    ('linux', 'x86', 'elf', ['-fPIC', '-DOPENSSL_IA32_SSE2'], 'S'),
    ('linux', 'x86_64', 'elf', [], 'S'),
    ('mac', 'x86_64', 'macosx', [], 'S'),
    # ('windows', 'aarch64', 'coff', [], 'S'),
    # ('windows', 'arm', 'coff', [], 'S'),
    ('windows', 'x86', 'win32n', [], 'S'),
    # ('windows', 'x86_64', 'coff', [], 'S'),
]


# NON_PERL_FILES enumerates assembly files that are not processed by the
# perlasm system.
NON_PERL_FILES = {
    ('linux', 'arm'): [
        'boringssl/crypto/curve25519/asm/x25519-asm-arm.S',
        'boringssl/crypto/poly1305/poly1305_arm_asm.S',
    ],
    ('linux', 'x86_64'): [
        'boringssl/crypto/hrss/asm/poly_rq_mul.S',
    ],
}


def FindCMakeFiles(directory):
    """Returns list of all CMakeLists.txt files recursively in directory."""
    cmakefiles = []

    for (path, _, filenames) in os.walk(directory):
        for filename in filenames:
            if filename == 'CMakeLists.txt':
                cmakefiles.append(os.path.join(path, filename))

    return cmakefiles


def ExtractPerlAsmFromCMakeFile(cmakefile):
    """Parses the contents of the CMakeLists.txt file passed as an argument and
    returns a list of all the perlasm() directives found in the file."""
    perlasms = []
    with open(cmakefile) as f:
        for line in f:
            line = line.strip()
            if not line.startswith('perlasm('):
                continue
            if not line.endswith(')'):
                raise ValueError('Bad perlasm line in %s' % cmakefile)
            # Remove "perlasm(" from start and ")" from end
            params = line[8:-1].split()
            if len(params) < 4:
                raise ValueError('Bad perlasm line in %s: %s' % (cmakefile, line))
            perlasms.append({
                'arch': params[1],
                'output': os.path.join(os.path.dirname(cmakefile), params[2]),
                'input': os.path.join(os.path.dirname(cmakefile), params[3]),
                'extra_args': params[4:],
            })

    return perlasms


def ReadPerlAsmOperations():
    """Returns a list of all perlasm() directives found in CMake config files in
    src/."""
    perlasms = []
    cmakefiles = FindCMakeFiles('boringssl')

    for cmakefile in cmakefiles:
        perlasms.extend(ExtractPerlAsmFromCMakeFile(cmakefile))

    return perlasms


def PerlAsm(output_filename, input_filename, perlasm_style, extra_args):
    """Runs the a perlasm script and puts the output into output_filename."""
    base_dir = os.path.dirname(output_filename)
    if not os.path.isdir(base_dir):
        os.makedirs(base_dir)
    subprocess.check_call(
        ['perl', input_filename, perlasm_style] + extra_args + [output_filename])


def WriteAsmFiles(perlasms):
    """Generates asm files from perlasm directives for each supported OS x
    platform combination."""
    asmfiles = {}

    for perlasm in perlasms:
        for (osname, arch, perlasm_style, extra_args, asm_ext) in OS_ARCH_COMBOS:
            if arch != perlasm['arch']:
                continue
            key = (osname, arch)
            outDir = '%s-%s' % key

            output = perlasm['output']
            if not output.startswith('boringssl/crypto'):
                raise ValueError('output missing crypto: %s' % output)
            output = os.path.join(outDir, output[17:])
            output = '%s-%s.%s' % (output, osname, asm_ext)
            per_command_extra_args = extra_args + perlasm['extra_args']
            PerlAsm(output, perlasm['input'], perlasm_style, per_command_extra_args)
            asmfiles.setdefault(key, []).append(output)

    return asmfiles


def preprocessor_arch_for_arch(arch):
    if arch == "arm":
        return "__arm__"
    elif arch == "aarch64":
        return "__aarch64__"
    elif arch == "x86":
        return "__i386__"
    elif arch == "x86_64":
        return "__x86_64__"


def preprocessor_platform_for_os(osname):
    if osname == 'mac' or osname == 'ios':
        return '__APPLE__'
    elif osname == 'linux':
        return '__linux__'
    elif osname == 'windows':
        return '_WIN32'


def asm_target(osname, arch, asm):
    components = asm.split('/')
    new_components = ["boringssl/crypto"] + components[1:-1] + [components[-1].replace('.S', '.' + osname + '.' + arch + '.S')]  # noqa: E501
    return '/'.join(new_components)


def munge_file(pp_arch, pp_platform, source_lines, sink):
    """
    Wraps a single assembly file in appropriate defines.
    """
    sink.write(b"#if defined(%b) && defined(%b)\n" % (pp_arch.encode(), pp_platform.encode()))  # noqa: E501
    for line in source_lines:
        sink.write(line)

    sink.write(b"#endif  // defined(%b) && defined(%b)\n" % (pp_arch.encode(), pp_platform.encode()))  # noqa: E501


def munge_all_files(osname, arch, asms):
    """
    Puts the appropriate architecture #ifdefs around the asm.
    """
    for asm in asms:
        pp_arch = preprocessor_arch_for_arch(arch)
        pp_platform = preprocessor_platform_for_os(osname)
        target = asm_target(osname, arch, asm)

        with open(asm, 'rb') as source:
            with open(target, 'wb') as sink:
                munge_file(pp_arch, pp_platform, source, sink)


def main():
    # First, we build all the .S files using the helper from boringssl.
    asm_outputs = WriteAsmFiles(ReadPerlAsmOperations())

    # Now we need to bring over all the .S files, inserting our preprocessor
    # directives along the way. We do this to allow the C preprocessor to make
    # unneeded assembly files vanish.
    for ((osname, arch), asm_files) in asm_outputs.items():
        munge_all_files(osname, arch, asm_files)

    for ((osname, arch), asm_files) in NON_PERL_FILES.items():
        for asm_file in asm_files:
            with open(asm_file, 'rb') as f:
                lines = f.readlines()
            pp_arch = preprocessor_arch_for_arch(arch)
            pp_platform = preprocessor_platform_for_os(osname)

            with open(asm_file, 'wb') as sink:
                munge_file(pp_arch, pp_platform, lines, sink)


if __name__ == '__main__':
    main()
