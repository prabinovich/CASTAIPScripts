# Python 
import os
import sys
import argparse
import requests
import time
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Declare and initialize map for keeping Health Factors and Quality Standards contributing to each rule 
_gRuleHFDict = {}
_gRuleQualStdDict = {}

def getAppSnapshots(_apiUrl, _auth, _appName, _appResultsUri, _aipResultsFile):
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
            # Header: 'app_name,snapshot_name,snapshot_date,rule,critical_flag,grade,addedCriticalViolations,
                #    removedCriticalViolations,addedViolations,removedViolations,health_factors
            _aipResultsFile.write('"{}",{},{},{},{},{},{},{},{},{},{},{}\n'.format(_appname, 'no snapshots', 'no snapshots', 'no snapshots', 'no snapshots', 
                'no snapshots', 'no snapshots', 'no snapshots', 'no snapshots', 'no snapshots', 'no snapshots', 'no snapshots'))
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
    _restUri = '{}/results/?quality-indicators=(cc:60017,nc:60017)&select=(evolutionSummary)'.format(_snapshotResultsUri)
    
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
            _aipResultsFile.write('"{}",{},{},{},{},{},{},{},{},{},{},{}\n'.format(_appname, 'no metrics', 'no metrics', 'no metrics', 'no metrics', 
                    'no metrics', 'no metrics', 'no metrics', 'no metrics', 'no metrics', 'no metrics', 'no metrics'))
        else:
            # Get snapshot version info
            _snapshotName = _jsonResult[0]['version']
            _snapshotDate = _jsonResult[0]['date']['isoDate']
            
            # Loop through all rules and write results to file
            for item in _jsonResult[0]['applicationResults']:                
                # Check if JSON element is present, otherwise specify that data is unavailable
                _ruleType = item['type']
                _ruleName = item['reference']['name'] if ('reference' in item and 'name' in item['reference']) else 'n/a'
                _ruleHref = item['reference']['href'] if ('reference' in item and 'href' in item['reference']) else 'n/a'
                _ruleID = item['reference']['key'] if ('reference' in item and 'key' in item['reference']) else 'n/a'
                _ruleCriticalFlag = item['reference']['critical'] if ('reference' in item and 'critical' in item['reference']) else 'n/a'
                _ruleGrade = item['result']['grade'] if ('result' in item and 'grade' in item['result']) else 'n/a'
                
                if ('result' in item and 'evolutionSummary' in item['result']):
                    _addedCriticalViolations = item['result']['evolutionSummary']['addedCriticalViolations']
                    _removedCriticalViolations = item['result']['evolutionSummary']['removedCriticalViolations']
                    _addedViolations = item['result']['evolutionSummary']['addedViolations']
                    _removedViolations = item['result']['evolutionSummary']['removedViolations']
                else:
                    _addedCriticalViolations = 'n/a'
                    _removedCriticalViolations = 'n/a'
                    _addedViolations = 'n/a'
                    _removedViolations = 'n/a'
                
                # Get health factors that rule is contributing to
                _ruleHealthFactors, _ruleQualityStandards = getRuleHFs(_apiUrl, _auth, _ruleID, _ruleName, _ruleHref)
                
                # Write the info only if there is a change in the rule
                if ((_addedCriticalViolations == 0 and _removedCriticalViolations == 0
                    and _addedViolations == 0 and _removedViolations == 0) or (_ruleType != 'quality-rules')):
                    pass # Skip if no changes to violations
                else:
                    # Header: 'app_name,snapshot_name,snapshot_date,rule,critical_flag,grade,addedCriticalViolations,
                    #    removedCriticalViolations,addedViolations,removedViolations,health_factors,quality_standards
                    _aipResultsFile.write('"{}","{}","{}","{}","{}",{},{},{},{},{},"{}","{}"\n'.format(_appName, _snapshotName, _snapshotDate, _ruleName, 
                        _ruleCriticalFlag, _ruleGrade, _addedCriticalViolations, _removedCriticalViolations, _addedViolations, 
                        _removedViolations, _ruleHealthFactors, _ruleQualityStandards))

    except Exception as e:
        print('***********************************************')
        print('Error: {}'.format(str(e)))
        print('***********************************************')
    
    return (1)

def getRuleHFs(_apiUrl, _auth, _ruleID, _ruleName, _ruleInfoUri):
    _headers = {'Accept':'application/json'}
    # Get the list of all snapshots
    _restUri = '{}'.format(_ruleInfoUri)
    
    try:
        # Check if the contributing info available in dictionary
        if (_ruleID in _gRuleHFDict) and (_ruleID in _gRuleQualStdDict):
            # print('Pull rule info from dictionary')
            # Pull HF from dictionary
            _ruleHealthFactors = _gRuleHFDict[_ruleID]
            _ruleQualityStandards = _gRuleQualStdDict[_ruleID]
            
        else:
            try:
                # print('Making a call to get rule info')
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

            # See if rule pattern is available
            _ruleQualityStandards = ''
            if 'rulePattern' not in _jsonResult:
                _ruleQualityStandards = 'none'
            else:
                # Make the call to pull that information
                _rulePatternURI = _jsonResult['rulePattern']['href']
                _ruleQualityStandards = getRuleQualityStandards(_apiUrl, _auth, _ruleID, _ruleName, _rulePatternURI)

            # Add HF info for new rule
            _gRuleQualStdDict[_ruleID] = _ruleQualityStandards

    except Exception as e:
        print('***********************************************')
        print('Error: {}'.format(str(e)))
        print('***********************************************')
    
    return (_ruleHealthFactors, _ruleQualityStandards)

def getRuleQualityStandards(_apiUrl, _auth, _ruleID, _ruleName, _rulePatternURI):
    _headers = {'Accept':'application/json'}
    # Get the list of all snapshots
    _restUri = '{}'.format(_rulePatternURI)
    
    try:
        # Check if info available in dictionary
        if (_ruleID in _gRuleQualStdDict):
            # Pull from dictionary
            _ruleQualityStandards = _gRuleQualStdDict[_ruleID]
        else:
            try:
                # print('Making a call to get rule quality standards info')
                _jsonResult = requests.get(_apiUrl+'/'+_restUri, headers=_headers, auth=_auth, verify=False, timeout=30).json()
                # print('1st RestAPI quality standards call succeeded.')
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
            _ruleQualityStandards = ''
            if len(_jsonResult['qualityStandards']) == 0:
                _ruleQualityStandards = 'none'
            else:
                # Loop through and collect contributing health factors
                for item in _jsonResult['qualityStandards']:
                    if _ruleQualityStandards == '':
                        _ruleQualityStandards = '{}({})'.format(item['id'], item['standard'])
                    else:
                        _ruleQualityStandards = _ruleQualityStandards + ',' + '{}({})'.format(item['id'], item['standard'])

    except Exception as e:
        print('***********************************************')
        print('Error: {}'.format(str(e)))
        print('***********************************************')
    
    return (_ruleQualityStandards)

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
        _aipresultsfile.write('app_name,snapshot_name,snapshot_date,rule,critical_flag,grade,addedCriticalViolations,' +
            'removedCriticalViolations,addedViolations,removedViolations,health_factors,quality_standards\n')

        # Get list of all applications
        _headers = {'Accept':'application/json'}
        _resturi = 'AAD/results?applications=($all)'
        
        print('Attempting to get a list of applications...')
        _jsonResult = requests.get(_args.connection+'/'+_resturi, headers=_headers, auth=_auth, verify=False, timeout=30).json()
        print('Call succeeded! Found {} applications.'.format(len(_jsonResult)))

        # Loop through each application to get and store the analysis results
        for item in _jsonResult:
            print('Getting snapshots info for application "{}"'.format(item['application']['name']))
            getAppSnapshots(_args.connection, _auth, item['application']['name'], item['application']['href'], _aipresultsfile)
                 
        # Close file
        _aipresultsfile.close()
        print ('CAST AIP results information stored in file: {}'.format(_args.filepath))
        
    except Exception as e:
            print('Error: {}'.format(str(e)))

    sys.exit(0)
    
    