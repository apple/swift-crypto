#!/usr/bin/env python
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.md for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

import contextlib
import subprocess
import os


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
      if len(params) < 2:
        raise ValueError('Bad perlasm line in %s' % cmakefile)
      perlasms.append({
          'extra_args': params[2:],
          'input': os.path.join(os.path.dirname(cmakefile), params[1]),
          'output': os.path.join(os.path.dirname(cmakefile), params[0]),
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


def ArchForAsmFilename(filename):
  """Returns the architectures that a given asm file should be compiled for
  based on substrings in the filename."""

  if 'x86_64' in filename or 'avx2' in filename:
    return ['x86_64']
  elif ('x86' in filename and 'x86_64' not in filename) or '586' in filename:
    return ['x86']
  elif 'armx' in filename:
    return ['arm', 'aarch64']
  elif 'armv8' in filename:
    return ['aarch64']
  elif 'arm' in filename:
    return ['arm']
  elif 'ppc' in filename:
    # We aren't supporting ppc here.
    return []
  else:
    raise ValueError('Unknown arch for asm filename: ' + filename)


def WriteAsmFiles(perlasms):
  """Generates asm files from perlasm directives for each supported OS x
  platform combination."""
  asmfiles = {}

  for osarch in OS_ARCH_COMBOS:
    (osname, arch, perlasm_style, extra_args, asm_ext) = osarch
    key = (osname, arch)
    outDir = '%s-%s' % key

    for perlasm in perlasms:
      filename = os.path.basename(perlasm['input'])
      output = perlasm['output']
      if not output.startswith('boringssl/crypto'):
        raise ValueError('output missing crypto: %s' % output)
      output = os.path.join(outDir, output[17:])
      if output.endswith('-armx.${ASM_EXT}'):
        output = output.replace('-armx',
                                '-armx64' if arch == 'aarch64' else '-armx32')
      output = output.replace('${ASM_EXT}', asm_ext)

      if arch in ArchForAsmFilename(filename):
        PerlAsm(output, perlasm['input'], perlasm_style,
                perlasm['extra_args'] + extra_args)
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


def asm_target(osname, arch, asm):
    components = asm.split('/')
    new_components = ["boringssl/crypto"] + components[1:-1] + [components[-1].replace('.S', '.' + osname + '.' + arch + '.S')]
    return '/'.join(new_components)


def munge_file(pp_arch, pp_platform, source_lines, sink):
    """
    Wraps a single assembly file in appropriate defines.
    """
    sink.write("#if defined(%s) && defined(%s)\n" % (pp_arch, pp_platform))
    for line in source_lines:
        sink.write(line)

    sink.write("#endif  // defined(%s) && defined(%s)\n" % (pp_arch, pp_platform))


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
    for ((osname, arch), asm_files) in asm_outputs.iteritems():
        munge_all_files(osname, arch, asm_files)

    for ((osname, arch), asm_files) in NON_PERL_FILES.iteritems():
        for asm_file in asm_files:
             with open(asm_file, 'rb') as f:
                 lines = f.readlines()

             pp_arch = preprocessor_arch_for_arch(arch)
             pp_platform = preprocessor_platform_for_os(osname)
             
             with open(asm_file, 'wb') as sink:
                 munge_file(pp_arch, pp_platform, lines, sink)

if __name__ == '__main__':
    main()

