# -*- coding: utf-8 -*-
'''
Support for pam
'''
from __future__ import absolute_import
from collections import OrderedDict

# Import python libs
import os
import logging
import copy

# Import salt libs
import salt.utils

log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'pam'


def __virtual__():
    '''
    Set the virtual name for the module
    '''
    return __virtualname__


def _parse(contents=None, file_name=None):
    '''
    Parse a standard pam config file
    '''
    if contents:
        pass
    elif file_name and os.path.exists(file_name):
        with salt.utils.fopen(file_name, 'r') as ifile:
            contents = ifile.read()
    else:
        log.error('File "{0}" does not exist'.format(file_name))
        return False

    rules = []
    for line in contents.splitlines():
        if not line:
            continue
        if line.startswith('#'):
            continue
        control_flag = ''
        module = ''
        arguments = []
        comps = line.split()
        interface = comps[0]
        position = 1
        if comps[1].startswith('['):
            control_flag = comps[1].replace('[', '')
            for part in comps[2:]:
                position += 1
                if part.endswith(']'):
                    control_flag += ' {0}'.format(part.replace(']', ''))
                    position += 1
                    break
                else:
                    control_flag += ' {0}'.format(part)
        else:
            control_flag = comps[1]
            position += 1
        module = comps[position]
        if len(comps) > position:
            position += 1
            arguments = comps[position:]
        rules.append({'interface': interface,
                      'control_flag': control_flag,
                      'module': module,
                      'arguments': arguments})
    return rules


def read_file(file_name):
    '''
    This is just a test function, to make sure parsing works

    CLI Example:

    .. code-block:: bash

        salt '*' pam.read_file /etc/pam.d/login
    '''
    return _parse(file_name=file_name)

def get_rules(file_name, control_flag=None, interface=None,
              module=None, arguments=None):
    '''
    '''
    rules = read_file(file_name)
    matches = []
    for rule in rules:
        match = False
        if interface and interface == rule.get('interface'):
            match = True
        if control_flag and control_flag == rule.get('control_flag'):
            match = True
        if module and module == rule.get('module'):
            match = True
        if arguments and rule.get('arguments'):
            if all(i in rule['arguments'] for i in arguments):
                if all(i in arguments for i in rule['arguments']):
                    match = True
        if match:
            matches.append(rule)
    return matches

def insert_rule(file_name, interface=None, control_flag=None, module=None,
                  arguments=None):
    '''
    Insert a new rule in a pam file
    '''
    insert = read_file(file_name)
    for i, j in  enumerate(insert):
        if j['interface'] == interface:
            index = i+1
    insert.insert(index, {'interface':interface, 'control_flag':control_flag,'module':module, 'arguments':arguments})
    return insert

def write_rule(file_name):
    '''
    Write out rule to file
    '''
    output = read_file(file_name)
    fout = open('pam_output.txt','w')
    fout.write("#%PAM-1.0\n")
    fout.write("# This file is auto-generated.\n")
    fout.write("# User changes will be destroyed the next time authconfig is run.\n")
    old_interfaces = set()
    for  value  in output:
        if 'interface' in value and value['interface'] not in old_interfaces:
            old_interfaces.add(value['interface'])
            fout.write("\n")
        if 'control_flag' in value:
            if '=' in value['control_flag']:
                value['control_flag'] = '[{0}]'.format(value['control_flag'])
        fout.write('{0}{1} {2} '.format(value['interface'].ljust(12, ' '), value['control_flag'].ljust(13, ' '), value['module']))
        for item in value['arguments']:
            fout.write('{0} '.format(item))
        fout.write('\n')
    fout.close()
def update_rule(file_name, interface=None, control_flag=None, module=None,
                 arguments=None, new_interface=None, new_control_flag=None,
                 new_module=None, new_arguments=None):
    '''
    Replace rule in pam file
    '''
    update = read_file(file_name)
    for i, rule in enumerate(update):
        if interface and interface == rule.get('interface'):
            if module and module == rule.get('module'):
                index = i
    update.insert(index, {'interface':new_interface, 'control_flag':new_control_flag,'module':new_module, 'arguments':new_arguments})
    return update