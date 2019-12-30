from lib.common import helpers
import base64

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Shell',

            'Author': ['@harmj0y'],

            'Description': ('shell cmd'),

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
            'EventName' : {
                'Description'   :   'command to run.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'EventFilter' : {
                'Description'   :   'command to run.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'EventConsumer' : {
                'Description'   :   'command to run.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Payload' : {
                'Description'   :   'command to run.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ProcessName' : {
                'Description'   :   'command to run.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ScriptingEngine' : {
                'Description'   :   'command to run.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Version' : {
                'Description'   :   'dotnet version',
                'Required'      :   True,
                'Value'         :   '3.5'
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
        event_name=self.options['EventName']['Value']
        event_filter=self.options['EventFilter']['Value']
        event_consumer=self.options['EventConsumer']['Value']
        payload=self.options['Payload']['Value']
        process_name=self.options['ProcessName']['Value']
        scripting_engine=self.options['ScriptingEngine']['Value']
        return base64.b64encode(assembly)+','+base64.b64encode(event_name)+','+base64.b64encode(event_filter)+','+base64.b64encode(event_consumer)+','+base64.b64encode(payload)+','+base64.b64encode(process_name)+','+base64.b64encode(scripting_engine)
