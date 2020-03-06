# Python 
import os
import sys
import argparse
import requests
import time
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Declare and initialize map for keeping Health Factors contributing to each rule 
_gRuleHFDict = {}

def getAppResults(_apiUrl, _auth, _appName, _appResultsUri, _aipResultsFile):
    _headers = {'Accept':'application/json'}
    # Get the list of all snapshots
    _restUri = '{}/results/?snapshots=($all)'.format(_appResultsUri)
    
    try:
        try:
            print('Making a call to get rule results for {} app.'.format(_appName))
            _jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, auth=_auth, verify=False, timeout=30).json()
            #print('1st RestAPI call succeeded.')
        except requests.exceptions.RequestException as e:
            try:
                print('1st connection attempt to RestAPI failed. Trying again...')
                _jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, auth=_auth, verify=False, timeout=60).json()
                print('2nd call succeeded.')
            except requests.exceptions.RequestException as e:
                print('Failed to connect to RestAPI')
                print('Error: {}'.format(e))
                print('Aborting script...')
                sys.exit(0)
        
        # Check to see if there are any snapshots
        if len(_jsonResult) == 0:
            _aipResultsFile.write('{},"{}","{}","{}","{}","{}"\n'.format(_appid, _appname, 'no snapshots', 'no snapshots', 'no snapshots', 'no snapshots', 'no snapshots'))
        else:
            # Loop through each snapshot and get rule results
            for item in _jsonResult:
                print('Getting info for application "{}" snapshot "{}"'.format(item['application']['name'], item['version']))
                getSnapshotResults(_args.connection, _auth, item['application']['name'], item['applicationSnapshot']['href'], _aipresultsfile)

    except Exception as e:
        print('***********************************************')
        print('Error: {}'.format(str(e)))
        print('***********************************************')
    
    return (1)

def getSnapshotResults(_apiUrl, _auth, _appName, _snapshotResultsUri, _aipResultsFile):
    _headers = {'Accept':'application/json'}
    # Get quality rules results for a given snapshot
    _restUri = '{}/results/?quality-indicators=(quality-rules)&select=violationRatio'.format(_snapshotResultsUri)
    
    try:
        try:
            print('Attempting to make RestAPI call to get snapshot results...')
            _jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, auth=_auth, verify=False, timeout=30).json()
            #print('1st RestAPI call succeeded.')
        except requests.exceptions.RequestException as e:
            try:
                print('1st connection attempt to RestAPI failed. Trying again...')
                _jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, auth=_auth, verify=False, timeout=60).json()
                print('2nd call succeeded.')
            except requests.exceptions.RequestException as e:
                print('Failed to connect to RestAPI')
                print('Error: {}'.format(e))
                print('Aborting script...')
                sys.exit(0)
        
        # Check to see if there are any metrics for this snapshot
        if len(_jsonResult[0]['applicationResults']) == 0:
            _aipResultsFile.write('{},"{}","{}","{}","{}","{}"\n'.format(_appid, _appname, 'no metrics', 'no metrics', 'no metrics', 'no metrics', 'no metrics'))
        else:
            # Get snapshot version
            _snapshotName = _jsonResult[0]['version']
            # Loop through all rules and write results to file
            for item in _jsonResult[0]['applicationResults']:                
                # Check if JSON element is present, otherwise specify that data is unavailable
                _ruleName = item['reference']['name'] if ('reference' in item and 'name' in item['reference']) else 'n/a'
                _ruleHref = item['reference']['href'] if ('reference' in item and 'href' in item['reference']) else 'n/a'
                _ruleID = item['reference']['key'] if ('reference' in item and 'key' in item['reference']) else 'n/a'
                _ruleCriticalFlag = item['reference']['critical'] if ('reference' in item and 'critical' in item['reference']) else 'n/a'
                _ruleGrade = item['result']['grade'] if ('result' in item and 'grade' in item['result']) else 'n/a'
                
                if ('result' in item and 'violationRatio' in item['result']):
                    _ruleTotalChecks = item['result']['violationRatio']['totalChecks']
                    _ruleFailedChecks = item['result']['violationRatio']['failedChecks']
                    _ruleSuccessfulChecks = item['result']['violationRatio']['successfulChecks']
                else:
                    _ruleTotalChecks = 'n/a'
                    _ruleFailedChecks = 'n/a'
                    _ruleSuccessfulChecks = 'n/a'
                
                # Get health factors that rule is contributing to
                _ruleHealthFactors = getRuleInfo(_apiUrl, _auth, _ruleID, _ruleName, _ruleHref, _aipResultsFile)
                
                # Header: 'app_name,snapshot,rule,critical_flag,grade,total_checks,failed_checks,successful_checks,health_factors'
                _aipResultsFile.write('"{}","{}","{}","{}",{},{},{},{},"{}"\n'.format(_appName, _snapshotName, _ruleName, 
                    _ruleCriticalFlag, _ruleGrade, _ruleTotalChecks, _ruleFailedChecks, _ruleSuccessfulChecks, _ruleHealthFactors))

    except Exception as e:
        print('***********************************************')
        print('Error: {}'.format(str(e)))
        print('***********************************************')
    
    return (1)

def getRuleInfo(_apiUrl, _auth, _ruleID, _ruleName, _ruleInfoUri, _aipResultsFile):
    _headers = {'Accept':'application/json'}
    # Get the list of all snapshots
    _restUri = '{}'.format(_ruleInfoUri)
    
    try:
        # Check if the contributing info available in dictionary
        if (_ruleID in _gRuleHFDict):
            # Pull HF from dictionary
            _ruleHealthFactors = _gRuleHFDict[_ruleID]
        else:
            try:
                #print('Making a call to get rule info')
                _jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, auth=_auth, verify=False, timeout=30).json()
                #print('1st RestAPI call succeeded.')
            except requests.exceptions.RequestException as e:
                try:
                    print('1st connection attempt to RestAPI failed. Trying again...')
                    _jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, auth=_auth, verify=False, timeout=60).json()
                    print('2nd call succeeded.')
                except requests.exceptions.RequestException as e:
                    print('Failed to connect to RestAPI')
                    print('Error: {}'.format(e))
                    print('Aborting script...')
                    sys.exit(0)
            
            # Check to see if information is available
            _ruleHealthFactors = ''
            if len(_jsonResult['gradeAggregators']) == 0:
                _ruleHealthFactors = 'none'
            else:
                # Loop through and collect contributing health factors
                for item in _jsonResult['gradeAggregators'][0]['gradeAggregators']:
                    if _ruleHealthFactors == '':
                        _ruleHealthFactors = item['name']
                    else:
                         _ruleHealthFactors = _ruleHealthFactors + ',' + item['name']
                
                # Add HF info for new rule
                _gRuleHFDict[_ruleID] = _ruleHealthFactors

    except Exception as e:
        print('***********************************************')
        print('Error: {}'.format(str(e)))
        print('***********************************************')
    
    return (_ruleHealthFactors)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Retrieves analysis results for all applications using RestAPI.")
    parser.add_argument('-c', '--connection', action='store', dest='connection', required=True, help='Specifies URL to the CAST AIP RestAPI service')
    parser.add_argument('-u', '--username', action='store', dest='username', required=True, help='Username to connect to RestAPI')
    parser.add_argument('-p', '--password', action='store', dest='password', required=True, help='Password to connect to RestAPI')
    parser.add_argument('-f', '--filepath', action='store', dest='filepath', required=True, help='Path and name of CSV file where script results will be stored')
    parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0')
    
    _args = parser.parse_args()
    _auth = (_args.username, _args.password)

    try:
        # Create file where results of query will be stored
        _aipresultsfile = open(_args.filepath, "w")
        # Write file header
        _aipresultsfile.write('app_name,snapshot,rule,critical_flag,grade,total_checks,failed_checks,successful_checks,health_factors\n') 
    
        # Get list of all applications
        _headers = {'Accept':'application/json'}
        _resturi = 'AAD/results?applications=($all)'
    
        print('Attempting to get a list of applications...')
        _jsonResult = requests.get(_args.connection+'/'+_resturi, headers=_headers, auth=_auth, verify=False, timeout=30).json()
        print('Call succeeded! Found {} applications.'.format(len(_jsonResult)))

        # Loop through each application to get and store the analysis results
        for item in _jsonResult:
            print('Getting snapshots info for application "{}"'.format(item['application']['name']))
            getAppResults(_args.connection, _auth, item['application']['name'], item['application']['href'], _aipresultsfile)
                 
        # Close file
        _aipresultsfile.close()
        print ('CAST AIP results information stored in file: {}'.format(_args.filepath))
        
    except Exception as e:
            print('Error: {}'.format(str(e)))

    sys.exit(0)
    