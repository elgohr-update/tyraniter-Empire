from lib.common import helpers
import base64

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Wdigest',

            'Author': ['@harmj0y'],

            'Description': ('Wdigest'),

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
        return base64.b64encode(assembly)
