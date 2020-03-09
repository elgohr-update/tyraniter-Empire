from lib.common import helpers
import base64

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'PortScan',

            'Author': ['@harmj0y'],

            'Description': ('PortScan'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'dotnet',

            'MinLanguageVersion' : '1',
            
            'Comments': []
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'ComputerNames' : {
                'Description'   :   'command to run.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Ports' : {
                'Description'   :   'command to run.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Ping' : {
                'Description'   :   'command to run.',
                'Required'      :   True,
                'Value'         :   'true'
            },
            'Version' : {
                'Description'   :   'dotnet version',
                'Required'      :   True,
                'Value'         :   '45'
            },
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
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


    def generate(self, obfuscate=False, obfuscationCommand=""):
        #moduleSource=self.mainMenu.installPath+"/data/module_source/dotnet/"
        version=self.options['Version']['Value']
        assembly = helpers.get_dotnet_module_assembly(self.mainMenu.installPath,self.info["Name"],version)
        hostnames=self.options['ComputerNames']['Value']
        ports=self.options['Ports']['Value']
        ping=self.options['Ping']['Value']
        return base64.b64encode(assembly)+','+base64.b64encode(hostnames)+','+base64.b64encode(ports)+','+base64.b64encode(ping)
