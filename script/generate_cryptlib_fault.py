#!/usr/bin/env python3
#
#  Copyright Notice:
#  Copyright 2026 DMTF. All rights reserved.
#  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
#

"""Generates the crypto fault injection layer in unit_test/cryptlib_fault/.

The layer forwards every function of the crypto backend API to the backend, and lets a test make a
call fail or corrupt its output. It reads the declarations in include/hal/library/cryptlib/*.h and
os_stub/include/hal/library/cryptlib_ext.h, and writes
- cryptlib_fault_rename.h, which renames the backend's definitions to libspdm_real_*, and
- cryptlib_fault_forward.c, which defines the API names as forwarders to libspdm_real_*.

Run it from anywhere after a header changes. compliance-checks.yml fails if the output differs.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(REPO, 'unit_test', 'cryptlib_fault')
HEADERS = sorted(os.path.join('include', 'hal', 'library', 'cryptlib', name)
                 for name in os.listdir(os.path.join(REPO, 'include', 'hal', 'library',
                                                     'cryptlib'))
                 if name.endswith('.h'))
HEADERS.append(os.path.join('os_stub', 'include', 'hal', 'library', 'cryptlib_ext.h'))

COPYRIGHT = '''/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
'''

# Implemented outside the crypto backend, so the backend has nothing to rename.
NOT_IN_BACKEND = {'libspdm_get_random_number_64'}

# cryptlib_ext.h declares these without the condition that both backends define them under. A
# forwarder needs the backend's definition, so it is compiled only when both conditions hold.
DEFINITION_CONDITIONS = {
    'libspdm_x509_get_common_name': 'LIBSPDM_CERT_PARSE_SUPPORT',
    'libspdm_x509_get_organization_name': 'LIBSPDM_CERT_PARSE_SUPPORT',
    'libspdm_x509_get_issuer_common_name': 'LIBSPDM_CERT_PARSE_SUPPORT',
    'libspdm_x509_get_issuer_orgnization_name': 'LIBSPDM_CERT_PARSE_SUPPORT',
    'libspdm_x509_construct_certificate': 'LIBSPDM_CERT_PARSE_SUPPORT',
    'libspdm_x509_free': 'LIBSPDM_CERT_PARSE_SUPPORT',
    'libspdm_x509_stack_free': 'LIBSPDM_CERT_PARSE_SUPPORT',
    'libspdm_x509_get_tbs_cert': 'LIBSPDM_CERT_PARSE_SUPPORT',
    'libspdm_gen_x509_csr': 'LIBSPDM_CERT_PARSE_SUPPORT',
    'libspdm_rsa_get_private_key_from_pem':
        '(LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)',
    'libspdm_mldsa_get_private_key_from_pem': 'LIBSPDM_ML_DSA_SUPPORT',
    'libspdm_slhdsa_get_private_key_from_pem': 'LIBSPDM_SLH_DSA_SUPPORT',
    'libspdm_ecd_check_key': '(LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)',
    'libspdm_ecd_generate_key':
        '(LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)',
    'libspdm_dh_generate_parameter': 'LIBSPDM_FFDHE_SUPPORT',
    'libspdm_dh_set_parameter': 'LIBSPDM_FFDHE_SUPPORT',
}

# Forwarded without a fault point, because they cannot report failure.
NO_FAULT = {'libspdm_x509_compare_date_time'}

# Exceptions to the name rules in op_for().
OP_OVERRIDES = {
    'libspdm_ec_new_by_nid': 'DHE_NEW',
    'libspdm_dh_new_by_nid': 'DHE_NEW',
    'libspdm_dh_generate_parameter': 'DHE_NEW',
    'libspdm_dh_set_parameter': 'DHE_NEW',
    'libspdm_sm2_key_exchange_new_by_nid': 'DHE_NEW',
    'libspdm_sm2_key_exchange_init': 'DHE_NEW',
    'libspdm_dh_generate_key': 'DHE_GENERATE',
    'libspdm_ec_generate_key': 'DHE_GENERATE',
    'libspdm_sm2_key_exchange_generate_key': 'DHE_GENERATE',
    'libspdm_dh_compute_key': 'DHE_COMPUTE',
    'libspdm_ec_compute_key': 'DHE_COMPUTE',
    'libspdm_sm2_key_exchange_compute_key': 'DHE_COMPUTE',
    'libspdm_mlkem_new_by_name': 'KEM_NEW',
    'libspdm_mlkem_generate_key': 'KEM_GENERATE',
    'libspdm_mlkem_encapsulate': 'KEM_ENCAPSULATE',
    'libspdm_mlkem_encapsulate_ex': 'KEM_ENCAPSULATE',
    'libspdm_mlkem_decapsulate': 'KEM_DECAPSULATE',
    'libspdm_x509_verify_cert': 'X509_VERIFY',
    'libspdm_x509_verify_cert_chain': 'X509_VERIFY',
    'libspdm_gen_x509_csr': 'CSR',
    'libspdm_x509_construct_certificate': 'CSR',
    'libspdm_x509_construct_certificate_stack': 'CSR',
}

# On failure, these in/out sizes are 0, as the header defines. Any other output is left as it was.
FAIL_ZERO_SIZES = {
    'libspdm_x509_get_subject_name': ['subject_size'],
    'libspdm_x509_get_signature_algorithm': ['oid_size'],
    'libspdm_x509_get_issuer_name': ['issuer_size'],
    'libspdm_x509_get_extension_data': ['extension_data_size'],
    'libspdm_x509_get_validity': ['from_size', 'to_size'],
    'libspdm_x509_get_extended_key_usage': ['usage_size'],
    'libspdm_x509_get_extended_basic_constraints': ['basic_constraints_size'],
}

# The output that CORRUPT_OUTPUT changes, by operation. The first parameter of these names wins.
CORRUPT_OUTPUTS = {
    'HASH_ALL': ['hash_value'],
    'HASH_FINAL': ['hash_value'],
    'HMAC': ['hmac_value'],
    'HKDF_EXTRACT': ['prk_out'],
    'HKDF_EXPAND': ['out'],
    'AEAD_ENCRYPT': ['tag_out'],
    'AEAD_DECRYPT': ['data_out'],
    'RANDOM': ['output'],
    'ASYM_SIGN': ['signature'],
    'DHE_GENERATE': ['public_key', 'public_data'],
    'DHE_COMPUTE': ['key'],
    'KEM_GENERATE': ['encap_key'],
    'KEM_ENCAPSULATE': ['shared_secret'],
    'KEM_DECAPSULATE': ['shared_secret'],
}

# The size of a corrupted output, when no parameter gives it.
OUTPUT_SIZE_OVERRIDES = {'output': 'size', 'signature': 'sig_size', 'public_data': 'public_size'}

# The first line of a function declaration. Most declarations start with extern, but not all, and a
# function that is not forwarded bypasses the layer without a link error.
DECLARATION = re.compile(r'\s*(?:extern\s+)?(?!typedef\b)[A-Za-z_][\w \t*]*?\blibspdm_\w+\s*\(')


class Function:
    def __init__(self, name, ret, params, condition):
        self.name = name
        self.ret = ret
        self.params = params
        self.conditions = [condition]


def strip_comments(text):
    return re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), text, flags=re.S)


def parse_params(text):
    text = ' '.join(text.split())
    if text in ('', 'void'):
        return []
    params = []
    depth = 0
    current = ''
    for char in text:
        if char == ',' and depth == 0:
            params.append(current.strip())
            current = ''
            continue
        depth += {'(': 1, ')': -1}.get(char, 0)
        current += char
    params.append(current.strip())
    result = []
    for param in params:
        match = re.search(r'\(\s*\*\s*(\w+)\s*\)', param) or re.search(r'(\w+)\s*$', param)
        result.append((param, match.group(1)))
    return result


def parse_header(path, functions, order):
    text = strip_comments(open(os.path.join(REPO, path)).read().replace('\r\n', '\n'))
    guard = re.search(r'^\s*#\s*ifndef\s+(\w+)', text, re.M).group(1)
    stack = []
    statement = ''
    for line in text.split('\n'):
        directive = re.match(r'\s*#\s*(\w+)\s*(.*?)\s*$', line)
        if directive:
            keyword, argument = directive.groups()
            if keyword == 'ifndef' and argument == guard and not stack:
                stack.append(None)
            elif keyword == 'if':
                stack.append(argument)
            elif keyword == 'ifdef':
                stack.append('defined(%s)' % argument)
            elif keyword == 'ifndef':
                stack.append('!defined(%s)' % argument)
            elif keyword == 'endif':
                stack.pop()
            elif keyword in ('else', 'elif'):
                sys.exit('%s: #%s is not supported' % (path, keyword))
            continue
        if statement or line.lstrip().startswith('extern') or DECLARATION.match(line):
            statement += ' ' + line
            if ';' not in line:
                continue
            match = re.match(r'\s*(?:extern\s+)?(.*?)\b(libspdm_\w+)\s*\((.*)\)\s*;\s*$', statement,
                             re.S)
            statement = ''
            if not match:
                sys.exit('%s: cannot parse a declaration' % path)
            ret, name, params = ' '.join(match.group(1).split()), match.group(2), match.group(3)
            # A forwarder cannot pass on variadic arguments, so those functions keep their names.
            if name in NOT_IN_BACKEND or params.rstrip().endswith('...'):
                continue
            condition = ' && '.join('(%s)' % c for c in stack if c is not None)
            if name in functions:
                functions[name].conditions.append(condition)
            else:
                functions[name] = Function(name, re.sub(r'\s*\*\s*$', ' *', ret).strip(),
                                           parse_params(params), condition)
                order.append(name)


def op_for(function):
    name = function.name[len('libspdm_'):]
    if function.ret == 'void' or function.name in NO_FAULT:
        return None
    if function.name in OP_OVERRIDES:
        return OP_OVERRIDES[function.name]
    if re.match(r'(sha\d+|sha3_\d+|sm3_256)_', name):
        suffix = name.split('_')[-1]
        return {'new': 'HASH_NEW', 'init': 'HASH_INIT', 'update': 'HASH_UPDATE',
                'final': 'HASH_FINAL', 'duplicate': 'HASH_DUPLICATE', 'all': 'HASH_ALL'}[suffix]
    if name.startswith('hmac_'):
        return 'HMAC'
    if name.startswith('hkdf_'):
        return 'HKDF_EXTRACT' if name.endswith('_extract') else 'HKDF_EXPAND'
    if name.startswith('aead_'):
        return 'AEAD_ENCRYPT' if name.endswith('_encrypt') else 'AEAD_DECRYPT'
    if name == 'random_bytes':
        return 'RANDOM'
    if name.startswith(('asn1_', 'x509_')):
        return 'X509_PARSE'
    if re.search(r'_sign(_ex|_fips|_with_nid)?$', name):
        return 'ASYM_SIGN'
    if re.search(r'_verify(_fips|_with_nid)?$', name):
        return 'ASYM_VERIFY'
    if name.startswith(('rsa_', 'ec_', 'ecd_', 'sm2_', 'mldsa_', 'slhdsa_', 'mlkem_')):
        return 'ASYM_KEY'
    sys.exit('%s: no operation' % function.name)


def corrupt_output(function, op):
    names = {name: param for param, name in function.params}
    for output in CORRUPT_OUTPUTS.get(op, []):
        if output not in names:
            continue
        size = OUTPUT_SIZE_OVERRIDES.get(output, output + '_size')
        if size not in names:
            return output, '1'
        return output, ('*%s' % size) if '*' in names[size] else size
    return None


def condition_of(function):
    conditions = function.conditions
    if '' in conditions:
        condition = ''
    elif len(conditions) == 1:
        condition = conditions[0]
    else:
        condition = ' || '.join('(%s)' % c for c in conditions)
    definition = DEFINITION_CONDITIONS.get(function.name)
    if definition:
        condition = ' && '.join('(%s)' % c for c in (condition, definition) if c)
    return condition


def split_top_level(condition):
    """Splits a condition at its top-level && and || operators, keeping the operators."""
    parts = []
    depth = 0
    start = 0
    index = 0
    while index < len(condition):
        char = condition[index]
        depth += {'(': 1, ')': -1}.get(char, 0)
        if depth == 0 and condition.startswith((' && ', ' || '), index):
            parts.append(condition[start:index + 3])
            start = index + 4
            index += 4
            continue
        index += 1
    parts.append(condition[start:])
    return parts


def if_lines(condition):
    lines = ['#if']
    for part in split_top_level(condition):
        if len(lines[-1]) + 1 + len(part) > 98 and lines[-1] != '#if':
            lines[-1] += ' \\'
            lines.append('   ')
        lines[-1] += ' ' + part
    return lines


def endif_line(condition):
    line = '#endif /* %s */' % condition
    if len(line) <= 100:
        return line
    return '#endif /* %s (...) */' % split_top_level(condition)[0]


def declaration(function, name):
    params = ', '.join(param for param, _ in function.params) or 'void'
    ret = function.ret
    if ret.endswith('*'):
        return '%s%s(%s)' % (ret, name, params)
    return '%s %s(%s)' % (ret, name, params)


def forwarder(function):
    real = function.name.replace('libspdm_', 'libspdm_real_', 1)
    args = ', '.join(name for _, name in function.params)
    op = op_for(function)
    lines = [declaration(function, function.name), '{']
    call = '%s(%s)' % (real, args)
    if op is None:
        lines.append('    %s%s;' % ('' if function.ret == 'void' else 'return ', call))
    else:
        corrupt = corrupt_output(function, op)
        hit = 'libspdm_crypto_fault_hit(LIBSPDM_CRYPTO_FAULT_OP_%s, %s)' % (
            op, 'true' if corrupt else 'false')
        failure = 'NULL' if function.ret.endswith('*') else 'false'
        fail_body = ['        if (%s != NULL) {\n            *%s = 0;\n        }' % (size, size)
                     for size in FAIL_ZERO_SIZES.get(function.name, [])]
        fail_body.append('        return %s;' % failure)
        if corrupt is None:
            lines += ['    if (%s ==' % hit,
                      '        LIBSPDM_CRYPTO_FAULT_ACTION_FAIL) {'] + fail_body + \
                     ['    }', '    return %s;' % call]
        else:
            output, size = corrupt
            lines += ['    libspdm_crypto_fault_action_t action;',
                      '    bool result;', '',
                      '    action = %s;' % hit,
                      '    if (action == LIBSPDM_CRYPTO_FAULT_ACTION_FAIL) {'] + fail_body + \
                     ['    }',
                      '    result = %s;' % call,
                      '    if (result && (action == LIBSPDM_CRYPTO_FAULT_ACTION_CORRUPT_OUTPUT)) {',
                      '        libspdm_crypto_fault_corrupt(%s, %s);' % (output, size),
                      '    }',
                      '    return result;']
    lines.append('}')
    return lines


def wrap_long_lines(lines):
    """Breaks the declarations that exceed 100 columns after a comma, aligned with the paren."""
    out = []
    for line in lines:
        if len(line) <= 100 or '(' not in line or line.startswith('#'):
            out.append(line)
            continue
        open_paren = line.index('(') + 1
        while len(line) > 100:
            cut = line.rfind(', ', open_paren, 100)
            if cut < 0:
                break
            out.append(line[:cut + 1])
            line = ' ' * open_paren + line[cut + 2:]
        out.append(line)
    return out


def main():
    functions = {}
    order = []
    for header in HEADERS:
        parse_header(header, functions, order)

    rename = [
        COPYRIGHT,
        '/* Generated by script/generate_cryptlib_fault.py. Do not edit. */', '',
        '/* Force-included into the crypto backend when CRYPTO_FAULT_INJECTION is ON, so that the',
        ' * backend defines libspdm_real_* and the forwarders own the API names. */', '',
        '#ifndef CRYPTLIB_FAULT_RENAME_H',
        '#define CRYPTLIB_FAULT_RENAME_H', '',
    ]
    for name in order:
        rename.append('#define %s %s' % (name, name.replace('libspdm_', 'libspdm_real_', 1)))
    rename += ['', '#endif /* CRYPTLIB_FAULT_RENAME_H */', '']

    forward = [
        COPYRIGHT,
        '/* Generated by script/generate_cryptlib_fault.py. Do not edit. */', '',
        '#include "hal/library/cryptlib.h"',
        '#include "hal/library/cryptlib_ext.h"',
        '#include "cryptlib_fault.h"', '',
        '/* This file is compiled into the crypto backend, with cryptlib_fault_rename.h, so the',
        ' * headers above declare the backend\'s functions with their libspdm_real_ names. The',
        ' * forwarders below take the API names back. */',
    ]
    for name in order:
        forward.append('#undef %s' % name)
    for name in order:
        function = functions[name]
        condition = condition_of(function)
        forward.append('')
        if condition:
            forward += if_lines(condition)
        forward += forwarder(function)
        if condition:
            forward.append(endif_line(condition))
    forward.append('')

    for file_name, lines in (('cryptlib_fault_rename.h', rename),
                             ('cryptlib_fault_forward.c', forward)):
        text = '\n'.join(wrap_long_lines('\n'.join(lines).split('\n')))
        with open(os.path.join(OUT_DIR, file_name), 'w', newline='\n') as output:
            output.write(text)


if __name__ == '__main__':
    main()
