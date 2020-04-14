# Python 
import os
import sys
import argparse
import requests
import urllib.parse
import time
import re
import json
import subprocess
import tempfile
import shutil
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from sys import prefix
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Declare global variables
_gAppSnapshotsInfo = {} # application snapshot info
_gApiUrl = '' # console API URL

# Will retrieve the list of snapshots for specified application
# Will return True or False depending if mentioned application exists on AIP Console server
def getAppSnapshots(_consoleSession, _appName):
    
    # Define URI to get list of all applications 
    _restUri = 'applications'
    
    _headers = {
        'Accept':'application/json',
        'X-XSRF-TOKEN': _consoleSession.cookies['XSRF-TOKEN']
    }

    try:
        #_jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, verify=False, timeout=30).json()
        _jsonResult = _consoleSession.get(_gApiUrl+'/'+_restUri, verify=False, timeout=30).json()
    except requests.exceptions.RequestException as e:
        try:
            print('1st connection attempt to RestAPI failed. Trying again...')
            _jsonResult = requests.get(_gApiUrl+'/'+_restUri, headers=_headers, verify=False, timeout=60).json()
            print('2nd call succeeded.')
        except requests.exceptions.RequestException as e:
            print('Failed to connect to RestAPI')
            print('Error: {}'.format(e))
            print('Aborting script...')
            sys.exit(0)
    
    # Check to see if information is available
    _appGuid = ''
    if 'applications' in _jsonResult:
        if len(_jsonResult['applications']) == 0:
            print ('No applications found on specified AIP Console server')
        else:
            print ('Found {} configured applications. Retrieving their info.'.format(len(_jsonResult['applications'])))
            # Loop through all apps and look for one of interest
            for _app in _jsonResult['applications']:
                # Check if the name of the app on list matches one of interest
                if _app['name'] == _appName:
                    _appGuid = _app['guid']
                    print ('Detected application "{}"... Bingo!'.format(_app['name']))
                    print ('This is our target application. Saving snapshot info.')
                    # If this is our app, save info about its snapshots
                    for _snapshot in _app['versions']:
                        print ('Saving information for snapshot "{}"'.format(_snapshot['name']))
                        _gAppSnapshotsInfo[_snapshot['name']] = _snapshot
                else:
                    print ('Detected application "{}"... skipping.'.format(_app['name']))
    else:
        print ('Error occured')
        print ('Json: {}'.format(str(_jsonResult)))
    
    return (_appGuid)

# Analyze an app
def runAnalysis(_consoleSession, _appGuid, _versionName, _releaseDate, _sourceZip):
    # Define URI to get list of all applications 
    _restUri = 'jobs'
    
    _headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'X-XSRF-TOKEN': _consoleSession.cookies['XSRF-TOKEN']
    }
    _data = """{
        "jobParameters": {
            "appGuid": \"""" + _appGuid + """\",
            "versionName": \"""" + _versionName + """\",
            "releaseDate": \"""" + str.format("{}T00:00:00.000Z", _releaseDate) + """\",
            "sourceArchive": \"""" + _sourceZip + """\"
          },
        "jobType": "ADD_VERSION"
    }"""

    _jobGuid = ''
    try:
        _result = _consoleSession.post(_gApiUrl+'/'+_restUri, headers=_headers, data=_data, verify=False, timeout=30)
        if _result.status_code == 201:
            _jobGuid = _result.json()['jobGuid']
            print ('Scan request succeeded. Job ID: {}'.format(_jobGuid))
            pollAndWaitForJobFinished(_consoleSession, _jobGuid)
        else:
            print ('1st request for code scan failed with error code {}'.format(_result.status_code))
            print ('Detailed response:')
            print (_result.json())
    except requests.exceptions.RequestException as e:
        try:
            print('1st attempt to code scan failed. Trying again...')
            _result = _consoleSession.post(_gApiUrl+'/'+_restUri, headers=_headers, data=_data, verify=False, timeout=30)
            if _result.status_code == 201:
                _jobGuid = _result.json()['jobGuid']
                print ('Scan request succeeded. Job ID: {}'.format(_jobGuid))
                pollAndWaitForJobFinished(_consoleSession, _jobGuid)
            else:
                print ('2nd request for code scan failed with error code {}'.format(_result.status_code))
                print ('Detailed response:')
                print (_result.json())
        except requests.exceptions.RequestException as e:
            print('Failed to connect to RestAPI')
            print('Error: {}'.format(e))
            print('Aborting script...')
            sys.exit(0)
    
    return (_jobGuid)

# Keep checking on status of the job and wait until it completes
# Return true/false job completion status
def pollAndWaitForJobFinished(_consoleSession, _jobGuid):
    # Define URI to get list of all applications 
    _restUri = 'jobs'
    
    _headers = {
        'Accept':'application/json',
        'X-XSRF-TOKEN': _consoleSession.cookies['XSRF-TOKEN']
    }

    _bJobSucceeded = False
    _jobState = ''
    try:
        _jobState = 'starting'
        while _jobState == 'starting' or _jobState == 'started':
            _result = _consoleSession.get(_gApiUrl+'/'+_restUri+'/'+_jobGuid, headers=_headers, verify=False, timeout=30)
            if _result.status_code == 200:
                _jobState = _result.json()['state']
                # if job status is not completed sleep for 5 seconds
                if _jobState == 'starting' or _jobState == 'started':
                    print ('Job status: {}. Sleeping for 5 seconds'.format(_jobState))
                    time.sleep(5)
                else:
                    _jobState = _result.json()['state']
                    if _jobState == 'completed':
                        print ('Job succeeded!')
                        _bJobSucceeded = True
                    else:
                        print ('Job failed with status {}'.format(_jobState))
                        print ('Error details:')
                        print (_result.json())
                        _bJobSucceeded = False
            else:
                print ('Error {} getting job status'.format(_result.status_code))
                print ('Detailed response:')
                print (_result.json())
                _bJobSucceeded = False
                _jobState = 'completed'
    except requests.exceptions.RequestException as e:
        print('Connection to Console API failed')
        print('Error: {}'.format(e))
        print('Aborting script...')
        sys.exit(0)
    
    return (_jobGuid)

# Analyze an app
def registerNewApp(_consoleSession, _appName):
    # Define URI to get list of all applications 
    _restUri = 'jobs'
    
    _headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'X-XSRF-TOKEN': _consoleSession.cookies['XSRF-TOKEN']
    }
    _data = """{
        "jobParameters": {
            "appName": \"""" + _appName + """\"
          },
        "jobType": "DECLARE_APPLICATION"
    }"""

    _appGuid = ''
    try:
        _result = _consoleSession.post(_gApiUrl+'/'+_restUri, headers=_headers, data=_data, verify=False, timeout=30)
        if _result.status_code == 201:
            print('Application registration request succeeded.')
            _appGuid = _result.json()['appGuid']
            _jobGuid = _result.json()['jobGuid']
            # poll and wait for the job to be completed
            pollAndWaitForJobFinished(_consoleSession, _jobGuid)    
        else:
            print ('Failed to request code analysis with error code {}'.format(_result.status_code))
            print ('Detailed response:')
            print (_result.json())
    except requests.exceptions.RequestException as e:
        try:
            print('1st connection attempt to RestAPI failed. Trying again...')
            _jsonResult = _consoleSession.post(_gApiUrl+'/'+_restUri, headers=_headers, data=_data, verify=False, timeout=60).json()
            if _result.status_code == 201:
                print('2nd request to register application succeeded.')
                _appGuid = _result.json()['appGuid']
                _jobGuid = _result.json()['jobGuid']
                pollAndWaitForJobFinished(_consoleSession, _jobGuid)
            else:
                print ('Failed to request code analysis with error code {}'.format(_result.status_code))
                print ('Detailed response:')
                print (_result.json())
        except requests.exceptions.RequestException as e:
            print('Failed to connect to RestAPI')
            print('Error: {}'.format(e))
            print('Aborting script...')
            sys.exit(0)

    return (_appGuid)

# Remove any special characters from tag name
def replaceSpecialChars(_inStr):
    _outStr = re.sub(r'\\', '_', _inStr)
    _outStr = re.sub(r'\/', '_', _inStr)
    
    return (_outStr)

# Initialize session to console API
def initConsoleSession(_apiKey):
    # Define URI to get list of all applications 
    _restUri = ''
    
    _headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'X-API-KEY':_apiKey
    }

    try:
        _consoleSession = requests.session()
        _result = _consoleSession.get(_gApiUrl+'/'+_restUri, headers=_headers, verify=False, timeout=30)
        if _result.status_code == 200:
            print ('Connection to AIP Console established successfully')
        else:
            print ('Failed to establish AIP Console session. Error code {}'.format(_result.status_code))
            print ('Detailed response:')
            print (_result.json())
            sys.exit(0)
    except requests.exceptions.RequestException as e:
        try:
            print('1st connection attempt to RestAPI failed. Trying again...')
            _result = _consoleSession.get(_gApiUrl+'/'+_restUri, headers=_headers, verify=False, timeout=30)
            if _result.status_code == 200:
                print ('2nd connection attempt succeeded. Session to AIP Console established successfully')
            else:
                print ('Failed to establish AIP Console session. Error code {}'.format(_result.status_code))
                print ('Detailed response:')
                print (_result.json())
                sys.exit(0)
        except requests.exceptions.RequestException as e:
            print('Failed to connect to RestAPI')
            print('Error: {}'.format(e))
            print('Aborting script...')
            sys.exit(0)

    return (_consoleSession)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Will analyzes all tags for a given Git repo using AIP Console.")
    parser.add_argument('-a', '--app', action='store', dest='app', required=True, help='Name of the application to scan (ex: foo)')
    parser.add_argument('-r', '--repo', action='store', dest='repo', required=True, help='Git repo location for downloading source (ex: github.com)')
    parser.add_argument('-t', '--regx', action='store', dest='regx', required=True, help='Regular expression representing which Git repo tags to analyze (ex: prod)')
    parser.add_argument('-c', '--api', action='store', dest='api', required=True, help='URL for AIP Console API (ex: http://server:8081/api)')
    parser.add_argument('-k', '--key', action='store', dest='key', required=True, help='API key for accessing Console')
    parser.add_argument('-u', '--usr', action='store', dest='usr', required=False, help='Git repository user')
    parser.add_argument('-p', '--pwd', action='store', dest='pwd', required=False, help='Git repository password')
    
    parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0')
    
    _args = parser.parse_args()
    _gApiUrl = _args.api
    
    # Check if optional username parameter is passed and adjust URL to include it
    if _args.usr is not None:
        # Inject username/password into Git repo URL
        try:
            _repoTokens = re.match(r"(https?://)(.*)", _args.repo)
            _repoUrlCreds = _repoTokens.group(1) +  urllib.parse.quote(_args.usr) + ':' +  urllib.parse.quote(_args.pwd) + '@' + _repoTokens.group(2)
        except TypeError:
            print ('Invalid Git repository URL specified. Please correct.')
            sys.exit(0)
    else:
        # Repo without credentials will be used
        _repoUrlCreds = _args.repo

    try:
        # Initiate Console session
        _consoleSession = initConsoleSession(_args.key)
        
        # See if application has been analyzed already
        _appGuid = getAppSnapshots(_consoleSession, _args.app)
        if _appGuid != '':
            print ('Application found... analyze any new versions')
        else:
            print ('New application... registering new app')
            _appGuid = registerNewApp(_consoleSession, _args.app)
            if _appGuid == '':
                print ('Failed to register application with AIP Console. Exiting...')
                sys.exit(0)
        
        # Checkout code to a temp directory and scan each tag available
        with tempfile.TemporaryDirectory(prefix='CAST_Src_') as _tmpdirname:

            print('Created temporary directory: ' + _tmpdirname)
            # Clone target repository locally
            os.system('git clone ' + _repoUrlCreds + ' ' + _tmpdirname)

            # Get list of available tags
            ret = subprocess.check_output('cd /D ' + _tmpdirname + ' && git tag -l --format="%(creatordate:short)|%(refname:short)"', shell=True)
            # Covert byte sequence to an array
            tags = ret.decode('ascii').splitlines()
            
            # Loop through tags and get code for each tag
            for tag in tags:

                # Create an array of date and tag
                tagInfo = tag.split('|')
                
                print ('Processing tag: {} created on {}'.format(tagInfo[1], tagInfo[0]))
                
                # CHeck if the tag matches patters requested for analysis
                if re.match(_args.regx, tagInfo[1], re.I):
                    # Check if the tag has not yet been analyzed
                    if replaceSpecialChars(tagInfo[1]) not in _gAppSnapshotsInfo:
                        print ('Setting code version to the target tag: {}'.format(tagInfo[1]))
                        os.system('cd /D ' + _tmpdirname + ' && git checkout tags/' + tagInfo[1] + ' -f')
                        
                        with tempfile.TemporaryFile(prefix='CAST_Zip_') as _tmpFile:
                            #tempfile.TemporaryFile(mode, buffering, encoding, newline, suffix, prefix, dir)
                            # Create temporary zip file
                            _tmpFilePath = os.path.realpath(_tmpFile.name)
                            print ('Creating temporary ZIP file: {}.zip'.format(_tmpFilePath))
                            shutil.make_archive(_tmpFilePath, 'zip', _tmpdirname)
                            print ('Initializing analysis for app: "{}" tag: "{}"'.format(_args.app, tagInfo[1]))
                            runAnalysis(_consoleSession, _appGuid, replaceSpecialChars(tagInfo[1]), tagInfo[0],  (_tmpFilePath+'.zip').replace('\\','\\\\'))
                    else:
                        print ('Tag {} already analyzed... skipping'.format(tagInfo[1]))
                else:
                    print ('Tag {} did not match targeted pattern... skipping'.format(tagInfo[1]))

    except Exception as e:
            print('Error: {}'.format(str(e)))

    sys.exit(0)