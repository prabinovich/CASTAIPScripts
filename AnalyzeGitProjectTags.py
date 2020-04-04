# Python 
import os
import sys
import argparse
import requests
import time
import json
import subprocess
import tempfile
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Declare and initialize map for application snapshot info
_gAppSnapshotsInfo = {}
_gApiUrl = ''

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
                    print('Bingo! Target application found. Saving snapshot info.')
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
        'jobParameters': {
            'appGuid': '""" + _appGuid + """',
            'versionName': '""" + _versionName + """',
            'releaseDate': '""" + _releaseDate + """',
            'sourceArchive': '""" + _sourceZip + """'
          },
        'jobType': 'ADD_VERSION'
    }"""

    _jobGuid = ''
    try:
        _result = _consoleSession.post(_gApiUrl+'/'+_restUri, headers=_headers, data=_data, verify=False, timeout=30)
        if _result.status_code == 201:
            _jobGuid = _results.json()['jobGuid']
            print ('Scan request succeeded. Job ID: {}'.format(_jobGuid))
        else:
            print ('1st request for code scan failed with error code {}'.format(_result.status_code))
            print ('Detailed response:')
            print (_result.json())
    except requests.exceptions.RequestException as e:
        try:
            print('1st attempt to code scan failed. Trying again...')
            _result = _consoleSession.post(_gApiUrl+'/'+_restUri, headers=_headers, data=_data, verify=False, timeout=30)
            if _result.status_code == 201:
                _jobGuid = _results.json()['jobGuid']
                print ('Scan request succeeded. Job ID: {}'.format(_jobGuid))
            else:
                print ('2nd request for code scan failed with error code {}'.format(_result.status_code))
                print ('Detailed response:')
                print (_result.json())
        except requests.exceptions.RequestException as e:
            print('Failed to connect to RestAPI')
            print('Error: {}'.format(e))
            print('Aborting script...')
            sys.exit(0)
    
    return (_bSuccess)

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
    
    parser = argparse.ArgumentParser(description="Analyzes all tags for a given Git repo using AIP Console.")
    parser.add_argument('-a', '--app', action='store', dest='app', required=True, help='Name of the application to scan')
    parser.add_argument('-r', '--repo', action='store', dest='repo', required=True, help='Git repo URL location for downloading source')
    parser.add_argument('-c', '--api', action='store', dest='api', required=True, help='URL for AIP Console API')
    parser.add_argument('-k', '--key', action='store', dest='key', required=True, help='API key for accessing Console')
    parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0')
    
    _args = parser.parse_args()
    _gApiUrl = _args.api

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
        
        if False:
            # Checkout code to a temp directory and scan each tag available
            with tempfile.TemporaryDirectory() as tmpdirname:
                print('Created temporary directory: ', tmpdirname)
                
                # Clone target repository locally
                os.system('git clone ' + _args.repo + ' ' + tmpdirname)
    
                # Get list of available tags
                #ret = subprocess.check_output('git --git-dir=' + tmpdirname + '/.git tag')
                ret = subprocess.check_output('git --git-dir=' + tmpdirname + '/.git tag -l --format="%(creatordate:short)|%(refname:short)"')
                # Covert byte sequence to an array
                tags = ret.decode('ascii').splitlines()
                
                # Loop through tags and get code for each tag
                for tag in tags:
                   print ('Processing tag: ' + tag)
                   # Create an array of date and tag
                   tagInfo = tag.split('|')
                   # Checkout currently selected tag to temporary directory
                   os.system('git --git-dir=' + tmpdirname + '/.git checkout tags/' + tagInfo[1] + ' -f')
                   if tagInfo[1] == 'mybatis-spring-2.0.3':
                       print ('Initializing analysis of an application')
                       runAnalysis(_consoleSession, _appGuid, tagInfo[1], tagInfo[0],  "C:/Temp/GatorMail.zip")

    except Exception as e:
            print('Error: {}'.format(str(e)))

    sys.exit(0)