#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: KCertGen
Dev: K4YT3X
Date Created: September 28, 2018
Last Modified: November 14, 2018

Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt
(C) 2018 K4YT3X
"""

from avalon_framework import Avalon
import os
import readline
import subprocess
import sys
import traceback

VERSION = '1.0.0'
COMMANDS = [
    'GenCaCert',
    'GenUserCert',
    'Exit',
    'Quit',
]


class ShellCompleter(object):
    """ A Cisco-IOS-like shell completer

    This is a Cisco-IOS-like shell completer, that is not
    case-sensitive. If the command typed is not ambiguous,
    then execute the only command that matches. User does
    not have to enter the entire command.
    """

    def __init__(self, options):
        self.options = sorted(options)

    def complete(self, text, state):
        if state == 0:
            if text:
                self.matches = [
                    s for s in self.options if s and s.lower().startswith(text.lower())]
            else:
                self.matches = self.options[:]
        try:
            return self.matches[state]
        except IndexError:
            return None


class CACert:

    def __init__(self, output_directory):
        self.output_directory = output_directory

        if not os.path.isdir(self.output_directory):
            os.mkdir(self.output_directory)

        self.ca_key = '{}/ca-key.pem'.format(self.output_directory)
        self.ca_cert = '{}/ca-cert.pem'.format(self.output_directory)
        self.ca_template = '{}/ca.tmpl'.format(self.output_directory)
        self.common_name = ''
        self.organization = ''

    def generate(self):
        self.get_parameters()
        self._gen_ca_template()
        self._gen_ca_privkey()
        self._gen_ca_cert()

    def get_parameters(self):
        while self.common_name == '':
            self.common_name = Avalon.gets('CA Common Name: ')
        while self.organization == '':
            self.organization = Avalon.gets('Organization Name: ')

    def _gen_ca_privkey(self):
        os.system('certtool --generate-privkey --outfile {}'.format(self.ca_key))

    def _gen_ca_template(self):
        with open(self.ca_template, 'w') as ca_template:
            ca_template.write('cn = "{}"\norganization = "{}"\nserial = 1\nexpiration_days = -1\nca\nsigning_key\ncert_signing_key\ncrl_signing_key'.format(
                self.common_name, self.organization))
            ca_template.close()

    def _gen_ca_cert(self):
        commands = ['certtool', '--generate-self-signed', '--load-privkey',
                    self.ca_key, '--template', self.ca_template, '--outfile', self.ca_cert]
        subprocess.run(commands)


class UserCert:

    def __init__(self, username, password, ca_directory):
        self.username = username
        self.password = password
        self.ca_directory = ca_directory
        self.ca_key = '{}/ca-key.pem'.format(self.ca_directory)
        self.ca_cert = '{}/ca-cert.pem'.format(self.ca_directory)

    def generate(self):
        # self.get_parameters()

        # Set GNUTLS_PIN variable
        os.environ['GNUTLS_PIN'] = self.password
        self.output_directory = '{}/{}'.format(self.ca_directory, self.username)

        if not os.path.isdir(self.output_directory):
            os.mkdir(self.output_directory)

        # Set paths
        self.user_key = '{}/{}-key.pem'.format(self.output_directory, self.username)
        self.user_cert = '{}/{}-cert.pem'.format(self.output_directory, self.username)
        self.user_p12 = '{}/{}.p12'.format(self.output_directory, self.username)
        self.user_template = '{}/{}.tmpl'.format(self.output_directory, self.username)

        # Start generation
        self._gen_template()
        self._gen_user_key()
        self._gen_user_cert()
        self._to_p12()

    def get_parameters(self):
        while self.username == '':
            self.username = Avalon.gets('Username: ')

    def _gen_template(self):
        with open(self.user_template, 'w') as user_template:
            user_template.write(
                'cn = "{}"\nunit = "users"\nexpiration_days = 365\nsigning_key\ntls_www_client'.format(self.username))
            user_template.close()

    def _gen_user_key(self):
        Avalon.info('Generating user key')
        subprocess.run(['certtool', '--generate-privkey', '--password', self.password, '--outfile', self.user_key])
        Avalon.info('Done')

    def _gen_user_cert(self):
        Avalon.info('Generating user certificates')
        subprocess.run(['certtool', '--generate-certificate', '--load-privkey', self.user_key, '--load-ca-certificate', self.ca_cert, '--load-ca-privkey', self.ca_key, '--template', self.user_template, '--outfile', self.user_cert])
        Avalon.info('Done')

    def _to_p12(self):
        Avalon.info('Converting pem to p12')
        subprocess.run(['certtool', '--to-p12', '--load-privkey', self.user_key, '--pkcs-cipher', '3des-pkcs12', '--load-certificate', self.user_cert, '--p12-name', self.username, '--password', self.password, '--outfile', self.user_p12, '--outder'])
        Avalon.info('Done')


def print_help():
    """ Print help messages
    """
    help_lines = [
        '\n{}Commands are not case-sensitive{}'.format(
            Avalon.FM.BD, Avalon.FM.RST),
        'Interactive  // launch interactive shell',
        'GenCaCert',
        'GenUserCert',
        'Exit',
        'Quit',
        '',
    ]
    for line in help_lines:
        print(line)


def command_interpreter(commands):
    """ WGC shell command interpreter

    This function interprets commands from CLI or
    the interactive shell, and passes the parameters
    to the corresponding functions.
    """
    try:
        # Try to guess what the user is saying
        possibilities = [
            s for s in COMMANDS if s.lower().startswith(commands[1])]
        if len(possibilities) == 1:
            commands[1] = possibilities[0]

        if commands[1].replace(' ', '') == '':
            result = 0
        elif commands[1].lower() == 'help':
            print_help()
            result = 0
        elif commands[1].lower() == 'gencacert':
            cacert = CACert(commands[2])
            cacert.generate()
            result = 0
        elif commands[1].lower() == 'genusercert':
            usercert = UserCert(commands[2], commands[3], commands[4])
            usercert.generate()
            result = 0
        elif commands[1].lower() == 'exit' or commands[1].lower() == 'quit':
            Avalon.warning('Exiting')
            exit(0)
        elif len(possibilities) > 0:
            Avalon.warning('Ambiguous command \"{}\"'.format(commands[1]))
            print('Use \"Help\" command to list available commands')
            result = 1
        else:
            Avalon.error('Invalid command')
            print('Use \"Help\" command to list available commands')
            result = 1
        return result
    except IndexError:
        Avalon.error('Invalid arguments')
        print('Use \"Help\" command to list available commands')
        result = 0


def print_welcome():
    """ Print program name and legal information
    """
    print('UniCert {}'.format(VERSION))
    print('(C) 2018 K4YT3X')
    print('Licensed under GNU GPL v3')


def main():
    """ WireGuard Mesh Configurator main function

    This function controls the main flow of this program.
    """

    try:
        if sys.argv[1].lower() == 'help':
            print_help()
            exit(0)
    except IndexError:
        pass

    # Begin command interpreting
    try:
        if sys.argv[1].lower() == 'interactive' or sys.argv[1].lower() == 'int':
            print_welcome()
            # Set command completer
            completer = ShellCompleter(COMMANDS)
            readline.set_completer(completer.complete)
            readline.parse_and_bind('tab: complete')
            # Launch interactive trojan shell
            prompt = '{}[WGC]> {}'.format(Avalon.FM.BD, Avalon.FM.RST)
            while True:
                command_interpreter([''] + input(prompt).split(' '))
        else:
            # Return to shell with command return value
            exit(command_interpreter(sys.argv[0:]))
    except IndexError:
        Avalon.warning('No commands specified')
        print_help()
        exit(0)
    except (KeyboardInterrupt, EOFError):
        Avalon.warning('Exiting')
        exit(0)
    except Exception:
        Avalon.error('Exception caught')
        traceback.print_exc()
        exit(1)


if __name__ == '__main__':

    # Launch main function
    main()
