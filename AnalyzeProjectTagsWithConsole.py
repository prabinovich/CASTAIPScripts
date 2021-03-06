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
def runAnalysis(_consoleSession, _appGuid, _versionName, _releaseDate, _sourceZip):
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
            "releaseDate": \"""" + str.format("{}T00:00:00.000Z", _releaseDate) + """\",
            "sourcePath": \"upload:""" + _sourceZip + """\"
          },
        "jobType": "add_version"
    }"""

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
    parser.add_argument('--gitUrl', action='store', dest='gitUrl', required=True, help='Git repo URL for downloading source. Include project name (ex: https://github.com/prabinovich)')
    parser.add_argument('--repos', action='store', dest='repos', required=True, help='Git repo name(s) that will downloaded for analysis separated by commas')
    parser.add_argument('--dir', action='store', dest='dir', required=False, help='Local or network folder to include in analysis')
    parser.add_argument('--regx', action='store', dest='regx', required=True, help='Regular expression representing which Git repo tags to analyze (ex: prod)')
    parser.add_argument('--api', action='store', dest='api', required=True, help='URL for AIP Console API (ex: http://server:8081/api)')
    parser.add_argument('--key', action='store', dest='key', required=True, help='API key for accessing Console')
    parser.add_argument('--usr', action='store', dest='usr', required=False, help='Git repository user')
    parser.add_argument('--pwd', action='store', dest='pwd', required=False, help='Git repository password')
    
    parser.add_argument('-v','--version', action='version', version='%(prog)s 2.0')
    
    _args = parser.parse_args()
    _gApiUrl = _args.api
    _gApiKey = _args.key
    
    # Check if optional username parameter is passed and adjust URL to include it
    if _args.usr is not None:
        # Inject username/password into Git repo URL
        try:
            _repoTokens = re.match(r"(https?://)(.*)", _args.gitUrl)
            _repoUrlCreds = _repoTokens.group(1) +  urllib.parse.quote(_args.usr) + ':' +  urllib.parse.quote(_args.pwd) + '@' + _repoTokens.group(2)
        except TypeError:
            print ('Invalid Git repository URL specified. Please correct.')
            sys.exit(0)
    else:
        # Repo without credentials will be used
        _repoUrlCreds = _args.gitUrl
        
    # Get list of repos to include in analysis
    _gitRepos = _args.repos.split(',')

    # Check if folder parameter was passed and verify that the directory is valid
    if _args.dir is not None:
        if not os.path.isdir(_args.dir):
            print ('Directory specified in --dir parameter is invalid: ' + _args.dir)
            print ('Please correct')
            sys.exit(0)

    try:
        # Initiate Console session
        _consoleSession = initConsoleSession()
        
        # See if application has been analyzed already
        _appGuid = getAppGuid(_consoleSession, _args.app)
        if _appGuid != '':
            print ('Application found... analyze any new versions')
            # Get snapshots that have already been analyzed
            getAppSnapshots(_consoleSession, _args.app, _appGuid)
        else:
            print ('New application... registering new app')
            _appGuid = registerNewApp(_consoleSession, _args.app)
            if _appGuid == '':
                print ('Failed to register application with AIP Console. Exiting...')
                sys.exit(0)
        
        # Checkout code to a temp directory and scan each tag available
        with tempfile.TemporaryDirectory(prefix='CAST_Git_', dir=os.getcwd()) as _gitReposRoot: 

            print('Checking out code to the following directory: ' + _gitReposRoot)
            # Clone each target repository locally
            for _gitRepoName in _gitRepos:
                print ('Cloning repository: {}/{}.git'.format(_args.gitUrl, _gitRepoName))
                os.system('git clone {}/{}.git "{}/{}"'.format(_repoUrlCreds, _gitRepoName, _gitReposRoot, _gitRepoName))
            
            # Get list of available tags
            ret = subprocess.check_output('cd "' + _gitReposRoot + "/" + _gitRepos[0] + '" && git tag -l --format="%(creatordate:short)|%(refname:short)"', shell=True)
            # Covert byte sequence to an array
            tags = ret.decode('ascii').splitlines()
            
            # Check the total number of tags found in Git repository
            if len(tags) != 0:
                print ('Found {} tags in repo. Looking through them to find tags targeted for scans'.format(len(tags)))
            else:
                print ('Repo does not contain any tags... aborting')
            
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
                        # Get the version of the code based on current tag
                        for _gitRepoName in _gitRepos:
                            print ('Setting repo {} version to current tag {}'.format(_gitRepoName, tagInfo[1]))
                            _err = os.system('cd "' + _gitReposRoot + '/' + _gitRepoName + '" && git checkout tags/' + tagInfo[1] + ' -f')
                            if _err != 0:
                                print ('Error checking out repo tag "{}"... aborting.'.format(tagInfo[1]))
                                sys.exit(_err)
                        
                        with tempfile.TemporaryDirectory(prefix='CAST_SrcTmp_', dir=os.getcwd()) as _tmpsrcdirname:
                            # Copy Git directory tree into another temp directory while removing .git folders
                            shutil.copytree(_gitReposRoot, _tmpsrcdirname + "/1", ignore=ignore_patterns('.git'))
                            
                            # If supplementary folder has been provided, add it to the temporary folder to be included in delivery
                            if _args.dir is not None:
                                print ('Copying supplementary directory "{}"to include in code delivery'.format(_args.dir))
                                shutil.copytree(_args.dir, _tmpsrcdirname + '/1/' + os.path.basename(_args.dir))
                            
                            # Create temporary zip file
                            with tempfile.NamedTemporaryFile(prefix='CAST_SrcZip_', dir=os.getcwd()) as _zipFile:
                                # Get temp file name and path
                                _srczippath = os.path.realpath(_zipFile.name)
                                _srczipname = os.path.basename(_zipFile.name)
                                print ('Creating temporary ZIP file: {}.zip'.format(_srczippath))
                                shutil.make_archive(_srczippath, 'zip', _tmpsrcdirname + "/1")
                                print ('Initializing analysis for app: "{}" tag: "{}"'.format(_args.app, tagInfo[1]))
                                
                                _startTime = time.time()
                                print ('Analysis of {} starting at {}'.format(_args.app, time.ctime(_startTime)), flush=True)
                                
                                # Upload file from client to server
                                uploadFile(_consoleSession, _appGuid, (_srczippath+'.zip').replace('\\','\\\\'))
                                # Run application analysis
                                runAnalysis(_consoleSession, _appGuid, replaceSpecialChars(tagInfo[1]), tagInfo[0], '{}/{}.zip'.format(_args.app, _srczipname))
                                _endTime = time.time()
                                print('Analysis of {} completed at {}. Time elapsed {}.'.format(_args.app, time.ctime(_endTime), format_time(_endTime - _startTime)), flush=True)
                                
                                # Cleanup
                                if os.path.exists(_srczippath + '.zip'):
                                    os.remove(_srczippath + '.zip')
                    else:
                        print ('Tag {} already analyzed... skipping'.format(tagInfo[1]))
                else:
                    print ('Tag {} did not match targeted pattern... skipping'.format(tagInfo[1]))
        
    except Exception as e:
            print('Error: {}'.format(str(e)))

    sys.exit(0)