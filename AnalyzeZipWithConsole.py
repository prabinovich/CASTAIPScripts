# Python 
import os
import sys
import argparse
import requests
import urllib.parse
import time
from datetime import datetime
import re
import json
import subprocess
import tempfile
import shutil
from shutil import copytree, ignore_patterns
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from sys import prefix
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Declare global variables
_gAppSnapshotsInfo = {} # application snapshot info
_gApiUrl = '' # console API URL
_gApiKey = '' # console API Key

# Will retrieve application GUID based on the application name
def getAppGuid(_consoleSession, _appName):
    
    # Define URI to get list of all applications 
    _restUri = 'applications'
    
    _headers = {
        'Accept':'application/json',
        'X-API-KEY':_gApiKey,
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
                else:
                    print ('Detected application "{}"... skipping.'.format(_app['name']))
    else:
        print ('Error occured')
        print ('Json: {}'.format(str(_jsonResult)))
    
    return (_appGuid)

# Will retrieve application GUID based on the application name
def getAppSnapshots(_consoleSession, _appName, _appGuid):
    
    # Define URI to get list of versions for an application 
    _restUri = 'applications/{}/snapshots'.format(_appGuid)
    
    _headers = {
        'Accept':'application/json',
        'X-API-KEY':_gApiKey,
        'X-XSRF-TOKEN': _consoleSession.cookies['XSRF-TOKEN']
    }

    try:
        #_jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, verify=False, timeout=30).json()
        print ('Getting versions for application "{}"'.format(_appName))
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

    # extract version information from returned JSON
    # if error, print JSON and error message
    try:
        _snapCount = 0
        for _snapshot in _jsonResult:
            print ('Found "{}" snapshot in application "{}"'.format(_snapshot['versionName'], _snapshot['application']['name']))
            _gAppSnapshotsInfo[_snapshot['versionName']] = _snapshot
            _snapCount += 1
        
        print ('Found total of {} snapshots in the application "{}"'.format(_snapCount, _appName))
    
    except Exception as e:
        print ('Failed to get analyzed versions. Error: {}'.format(e))
        print ('Json: {}'.format(str(_jsonResult)))
        print ('Aborting script...')
        sys.exit(0)
    
    return _snapCount

def uploadFile(_consoleSession, _appGuid, _filepath):
    
    MAX_SIZE = 25 * 1024 * 1024
    
    with open(_filepath, 'rb') as myFile:

        # create upload
        _filename = os.path.basename(myFile.name)
        print("Creating new upload for app '{}' using file '{}'".format(_appGuid, _filename))

        _createUpload = "{}/applications/{}/upload".format(_gApiUrl, _appGuid)
        print(_createUpload)
        _filesize = os.stat(myFile.fileno()).st_size
        
        _headers = {
        'content-type': 'application/json',
        'X-API-KEY':_gApiKey,
        'X-XSRF-TOKEN': _consoleSession.cookies['XSRF-TOKEN']
        }
        _data = '''{{"fileName": "{}", "fileSize": {} }}'''.format(_filename, _filesize)
        create_response = _consoleSession.post(_createUpload, data=_data, headers=_headers, timeout=30)
        
        if create_response.status_code != 201:
            print("Unable to create upload. Status {} : {}".format(create_response.status_code, create_response.text))
            return 1

        upload_guid = create_response.json()['guid']
        if upload_guid == "" or len(upload_guid) <= 0:
            print ('Upload file creation failed (no uid was generated)')
            return 2

        chunk_idx = 1
        part_upload_url = "{}/{}".format(_createUpload, upload_guid)
        print("Upload created with uid {} for application {}".format(upload_guid, _appGuid))

        content_part = myFile.read(MAX_SIZE)
        last_status = 200
        # Update XSRF token from the cookies
        _headers = {
            'X-API-KEY':_gApiKey,
            'X-XSRF-TOKEN': _consoleSession.cookies['XSRF-TOKEN']
        }

        while content_part != b'':
            contentSize = len(content_part)

            uploadBody = '''{{ "chunkSize": "{}" }}'''.format(contentSize)

            _files = [
                ('metadata', ('metadata.json', uploadBody, 'application/json')),
                ('content', ('content', content_part, 'application/octet-stream'))
            ]

            print('Body is : \n{}'.format(uploadBody))

            upload_part = _consoleSession.patch(part_upload_url, files=_files, headers=_headers)

            # Per Adrien:  201 status should be replaced with 202
            # 200 is upload complete, 202 is partial upload complete (a chunk of the file is correctly uploaded)
            if upload_part.status_code not in [200, 202]:
                print("Error while uploading part : {}".format(upload_part.text))
                print("Occured while uploading chunk #{} (from offset {})".format(chunk_idx, myFile.tell()))
                return 3
            else:
                last_status = upload_part.status_code

            chunk_idx = chunk_idx + 1
            content_part = myFile.read(MAX_SIZE)
            # Update XSRF token from the cookies
            _headers = {
                'X-API-KEY':_gApiKey,
                'X-XSRF-TOKEN': _consoleSession.cookies['XSRF-TOKEN']
            }

    if last_status != 200:
        print('Upload not complete. Last return status was {} instead of 200'.format(last_status))
        return 4

    print('Uploaded file successfully in {} chunks of {}MB each'.format(chunk_idx-1, MAX_SIZE/(1024*1024)))
    print('Done')
    return 0

# Analyze an app
def runAnalysis(_consoleSession, _appGuid, _versionName, _sourceZip):
    print ("Starting application analysis")
    _restUri = 'jobs'
    _headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'X-API-KEY':_gApiKey,
        'X-XSRF-TOKEN': _consoleSession.cookies['XSRF-TOKEN']
    }
    _data = """{
        "jobParameters": {
            "appGuid": \"""" + _appGuid + """\",
            "versionName": \"""" + _versionName + """\",
            "releaseDate": \"""" + str.format("{}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.000Z", datetime.now().year, datetime.now().month, datetime.now().day, datetime.now().hour, datetime.now().minute, datetime.now().second) + """\",
            "sourcePath": \"upload:""" + _sourceZip + """\"
          },
        "jobType": "add_version"
    }"""

    print("runAnalysis API Payload: \n" + _data)

    _jobGuid = ''
    try:
        _result = _consoleSession.post(_gApiUrl+'/'+_restUri, headers=_headers, data=_data, verify=False, timeout=30)
        # If error, try to reestablish the session
        if _result.status_code != 201:
            print ('Session invalid... reconnecting.')
            _consoleSession = initConsoleSession()
            _result = _consoleSession.post(_gApiUrl+'/'+_restUri, headers=_headers, data=_data, verify=False, timeout=30)
        
        if _result.status_code == 201:
            _jobGuid = _result.json()['jobGuid']
            print ('Scan request succeeded. Job ID: {}'.format(_jobGuid))
            pollAndWaitForJobFinished(_consoleSession, _jobGuid)
        else:
            print ('1st request for code scan failed with error code {}'.format(_result.status_code))
            print ('Detailed response:')
            print (_result.json())
            print ('Analysis failed. Check Console logs for more information.')
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
        'X-API-KEY':_gApiKey,
        'X-XSRF-TOKEN': _consoleSession.cookies['XSRF-TOKEN']
    }

    _bJobSucceeded = False
    _jobState = ''
    try:
        _jobState = 'starting'
        while _jobState == 'starting' or _jobState == 'started':
            _result = _consoleSession.get(_gApiUrl+'/'+_restUri+'/'+_jobGuid, headers=_headers, verify=False, timeout=30)
            # If error, try to reestablish the session
            if _result.status_code != 200:
                print ('Session expired while polling... reconnecting.')
                _consoleSession = initConsoleSession()
                _result = _consoleSession.get(_gApiUrl+'/'+_restUri+'/'+_jobGuid, headers=_headers, verify=False, timeout=30)
            
            if _result.status_code == 200:
                _jobState = _result.json()['state']
                # if job status is not completed sleep for 5 seconds
                if _jobState == 'starting' or _jobState == 'started':
                    print ('Job status: {}. Sleeping for 30 seconds'.format(_jobState), flush=True)
                    time.sleep(30)
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
    
    return (_bJobSucceeded)

# Analyze an app
def registerNewApp(_consoleSession, _appName):
    # Define URI to get list of all applications 
    _restUri = 'jobs'
    
    _headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'X-API-KEY':_gApiKey,
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
def initConsoleSession():
    # Define URI to get list of all applications 
    _restUri = ''
    
    _headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'X-API-KEY':_gApiKey
    }

    try:
        _consoleSession = requests.session()
        _result = _consoleSession.get(_gApiUrl+'/'+_restUri, headers=_headers, verify=False, timeout=30)
        if _result.status_code == 200:
            print ('Connection session to AIP Console established successfully')
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

# Convert seconds into hour:minute:sec format
def format_time(seconds): 
    min, sec = divmod(seconds, 60) 
    hour, min = divmod(min, 60) 
    return "%dh %02dm %02ds" % (hour, min, sec)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Will analyzes all tags for a given Git repo using AIP Console.")
    parser.add_argument('--app', action='store', dest='app', required=True, help='Name of the application to scan (ex: foo)')
    parser.add_argument('--zip', action='store', dest='zip', required=True, help='Full path/name to the file containing source code to analyze')
    parser.add_argument('--label', action='store', dest='label', required=True, help='Name to assign to the version of the code that will be analyzed')
    parser.add_argument('--api', action='store', dest='api', required=True, help='URL for AIP Console API (ex: http://server:8081/api)')
    parser.add_argument('--key', action='store', dest='key', required=True, help='API key for accessing Console')
    
    parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0')
    
    _args = parser.parse_args()
    _gApiUrl = _args.api
    _gApiKey = _args.key
    
    # Check for existence of the provided ZIP file 
    if not os.path.exists(_args.zip):
        print ('Zip file specified in --zip parameter is invalid: ' + _args.zip)
        print ('Please correct and retry again.')
        sys.exit(0)

    try:
        # Initiate Console session
        _consoleSession = initConsoleSession()
        
        # See if application has been analyzed already
        _appGuid = getAppGuid(_consoleSession, _args.app)
        if _appGuid != '':
            print ('Application found... skipping registration')
            # Get snapshots that have already been analyzed
            getAppSnapshots(_consoleSession, _args.app, _appGuid)
        else:
            print ('New application... registering...')
            _appGuid = registerNewApp(_consoleSession, _args.app)
            if _appGuid == '':
                print ('Failed to register application with AIP Console. Exiting...')
                sys.exit(0)
        
            
        # Check if the tag has not yet been analyzed
        if replaceSpecialChars(_args.label) not in _gAppSnapshotsInfo:
            
            # Get temp file name and path
            _srczippath = os.path.realpath(_args.zip)
            _srczipname = os.path.basename(_args.zip)
            
            _startTime = time.time()
            print ('Analysis of {} starting at {}'.format(_args.app, time.ctime(_startTime)), flush=True)
            
            # Upload file from client to server
            uploadFile(_consoleSession, _appGuid, (_srczippath).replace('\\','\\\\'))
            # Run application analysis
            runAnalysis(_consoleSession, _appGuid, replaceSpecialChars(_args.label), '{}/{}'.format(_args.app, _srczipname))
            
            _endTime = time.time()
            print('Analysis of {} completed at {}. Time elapsed {}.'.format(_args.app, time.ctime(_endTime), format_time(_endTime - _startTime)), flush=True)
            
        else:
            print ('Version requested to be analyzed already exists for this application... skipping'.format(_args.label))

        
    except Exception as e:
            print('Error: {}'.format(str(e)))

    sys.exit(0)