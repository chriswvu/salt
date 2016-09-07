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
    insert.insert(index, {'interface':interface, 'control_flag':control_flag,'module':module})
    return insert
    