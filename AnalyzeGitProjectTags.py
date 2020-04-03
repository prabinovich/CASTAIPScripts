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

# Will retrieve the list of snapshots for specified application
# Will return True or False depending if mentioned application exists on AIP Console server
def getAppSnapshots(_apiUrl, _apiKey, _appName):
    
    # Define URI to get list of all applications 
    _restUri = 'applications'
    
    _headers = {
        'Accept':'application/json',
        'X-API-KEY':_apiKey
    }

    try:
        _jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, verify=False, timeout=30).json()
    except requests.exceptions.RequestException as e:
        try:
            print('1st connection attempt to RestAPI failed. Trying again...')
            _jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, verify=False, timeout=60).json()
            print('2nd call succeeded.')
        except requests.exceptions.RequestException as e:
            print('Failed to connect to RestAPI')
            print('Error: {}'.format(e))
            print('Aborting script...')
            sys.exit(0)
    
    # Check to see if information is available
    _isAppFound = False
    if 'applications' in _jsonResult:
        if len(_jsonResult['applications']) == 0:
            print ('No applications found on specified AIP Console server')
            _isAppFound = False
        else:
            print ('Found {} configured applications. Retrieving their info.'.format(len(_jsonResult['applications'])))
            # Loop through all apps and look for one of interest
            for _app in _jsonResult['applications']:
                # Check if the name of the app on list matches one of interest
                if _app['name'] == _appName:
                    _isAppFound = True
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
    
    return (_isAppFound)

# Analyze an app
def analyzeAppVersion(_apiUrl, _apiKey): #_appGuid, _versionName, _releaseDate, _sourceZip):
    # Define URI to get list of all applications 
    _restUri = 'jobs'
    
    _headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'X-API-KEY':_apiKey
    }
    _data = {
        'jobParameters': {
            'appGuid': 'ef871d4a-7974-4ff2-ae19-c48688ee0869',
            'versionName': 'v7',
            'releaseDate': '2020-07-17T00:00:00.000Z',
            'sourceArchive': 'C:/Temp/GatorMail.zip'
          },
        'jobType': 'ADD_VERSION'
    }

    _bSuccess = False
    try:
        _result = requests.post(_apiUrl+'/'+_restUri, headers=_headers, data=_data, verify=False, timeout=30)
        if _result.status_code == 201:
            _bSuccess = True
        else:
            _bSuccess = False
            print ('Failed to request code analysis with error code {}'.format(_result.status_code))
            print ('Detailed response:')
            print (_result.json())
    except requests.exceptions.RequestException as e:
        try:
            print('1st connection attempt to RestAPI failed. Trying again...')
            _jsonResult = requests.post(_apiUrl+'/'+_restUri, headers=_headers, data=_data, verify=False, timeout=60).json()
            print('2nd call succeeded.')
        except requests.exceptions.RequestException as e:
            print('Failed to connect to RestAPI')
            print('Error: {}'.format(e))
            print('Aborting script...')
            sys.exit(0)
    
    return (_bSuccess)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Analyzes all tags for a given Git repo using AIP Console.")
    parser.add_argument('-a', '--app', action='store', dest='app', required=True, help='Name of the application to scan')
    parser.add_argument('-r', '--repo', action='store', dest='repo', required=True, help='Git repo URL location for downloading source')
    parser.add_argument('-c', '--api', action='store', dest='api', required=True, help='URL for AIP Console API')
    parser.add_argument('-k', '--key', action='store', dest='key', required=True, help='API key for accessing Console')
    parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0')
    
    _args = parser.parse_args()
    #_auth = (_args.username, _args.password)

    try:
        # See if application has been analyzed already
        if getAppSnapshots(_args.api, _args.key, _args.app) == True:
            print ('Application found')
        else:
            print ('New application')
        
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
                   
        analyzeAppVersion(_args.api, _args.key)

    except Exception as e:
            print('Error: {}'.format(str(e)))

    sys.exit(0)