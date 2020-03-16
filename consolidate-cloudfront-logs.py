#!/usr/bin/env python3.6

import glob
import re
import os
import sys
import pprint
import gzip
import json
import boto3
import configparser


class ProcessLogs:
    aFIELDS = [
        'date',
        'time',
        'edge-location',
        'sc-bytes',
        'ip',
        'cs-method',
        'cs-host',
        'cs-uri-stem',
        'sc-status',
        'cs-referer',
        'cs-user-agent',
        'cs-uri-query',
        'cs-cookie',
        'x-edge-result-type',
        'x-edge-request-id',
        'x-host-header',
        'cs-protocol',
        'cs-bytes',
        'time-taken',
        'x-forwarded-for',
        'ssl-protocol',
        'ssl-cipher',
        'x-edge-response-result-type',
        'cs-protocol-version',
        'fle-status',
        'fle-encrypted-fields',
        'c-port',
        'time-to-first-byte',
        'x-edge-detailed-result-type',
        'sc-content-type',
        'sc-content-len',
        'sc-range-start',
        'sc-range-end'
    ]

    aAWS_CF_EDGE_LOCATIONS = None

    sAWS_CF_EDGE_LOCATION_FILE = 'cloudfront-edge-locations.json'

    sSCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

    sCONFIG_FILE = 'config.ini'

    oPrinter = pprint.PrettyPrinter(indent=4)

    oConfig = configparser.ConfigParser()

    oS3Client = None

    def errorMsg(self, sMsg):
        print("Error: " + sMsg)
        sys.exit(-1)

    def initConfig(self):
        """Initialize the configuration"""

        sConfigPath = '%s/%s' % (self.sSCRIPT_DIR, self.sCONFIG_FILE)
        if not os.path.exists(sConfigPath):
            self.errorMsg('no configuration file: %s' % sConfigPath)

        # Allow for case sensitivity in INI values
        self.oConfig.optionxform = str
        self.oConfig.read(sConfigPath)

    def getEdgeLocation(self, aRow):
        """Get the AWS CloudFront edge location by city, county"""

        if self.aAWS_CF_EDGE_LOCATIONS is None:
            sLocationPath = '%s/%s' % (self.sSCRIPT_DIR, self.sAWS_CF_EDGE_LOCATION_FILE)
            if not os.path.exists(sLocationPath):
                self.errorMsg('no edge location file: %s' % sLocationPath)
            with open(sLocationPath) as f:
                data = json.load(f)
                self.aAWS_CF_EDGE_LOCATIONS = data['nodes']

        sLocation = aRow['edge-location']
        sAirport = sLocation[0:3]
        if sAirport in self.aAWS_CF_EDGE_LOCATIONS.keys():
            aAirport = self.aAWS_CF_EDGE_LOCATIONS[sAirport]
            sLocation = '%s (%s, %s)' % (sLocation, aAirport['city'], aAirport['country'])
            aRow['edge-location'] = sLocation

    def getRow(self, sLine):
        """Convert the space-delimited line into a dict of AWS CloudFront fields"""
        oZip = zip(self.aFIELDS, sLine.split())
        aRow = dict(oZip)
        aRow['cs-user-agent'] = aRow['cs-user-agent'].replace('%20', ' ')

        if aRow['x-host-header']:
            aRow['host'] = aRow['x-host-header']
        else:
            aRow['host'] = aRow['cs-host']

        aRow['request'] = '%s %s' % (aRow['cs-method'], aRow['cs-uri-stem'])
        if aRow['cs-uri-query']:
            aRow['request'] = aRow['request'] + '?' + aRow['cs-uri-query']
        self.getEdgeLocation(aRow)
        return aRow

    def convertRow(self, aRow):
        """Convert from the CloudFront access log to an Apache-style HTTP server log"""
        return '%s %s [%s:%s +0000] "%s" bytes:%s secs:%s "%s" "%s" edge-location: %s edge-result:%s' % \
               (aRow['host'], aRow['ip'], aRow['date'], aRow['time'], aRow['request'], aRow['cs-bytes'],
                aRow['time-taken'], aRow['cs-referer'], aRow['cs-user-agent'],
                aRow['edge-location'], aRow['x-edge-result-type'])

    def processDay(self, sDay, sServer, aFiles):
        sOutputDir = self.oConfig['logs']['output-path']
        if not os.path.exists(sOutputDir):
            self.errorMsg("invalid output directory: %s" % sOutputDir)
        sTopPath = '%s/%s' % (sOutputDir, sServer)
        if not os.path.exists(sTopPath):
            os.mkdir(sTopPath)

        sDownloadPath = self.oConfig['logs']['download-path']
        sDayPath = '%s/%s.log' % (sTopPath, sDay)

        # Determine if any log files was modified after the compiled day file - return now if not
        if os.path.exists(sDayPath):
            bNewer = False
            iDayFileTime = os.path.getmtime(sDayPath)
            for sFile in aFiles:
                sInputPath = '%s/%s' % (sDownloadPath, sFile)
                if os.path.getmtime(sInputPath) > iDayFileTime:
                    bNewer = True
                    break
            if bNewer is False:
                print("%s - no new log files for %s" % (sServer, sDay))
                return

        print("%s - processing logs for %s" % (sServer, sDay))

        # Gather all the lines, throwing out the top two header lines
        aAllLines = []
        for sFile in aFiles:
            sInputPath = '%s/%s' % (sDownloadPath, sFile)
            with gzip.open(sInputPath, 'rb') as f:
                sContent = f.read()
            aLines = re.split("\n", sContent.decode('utf-8'))
            aLines.pop(0)
            aLines.pop(0)
            aAllLines.extend(aLines)

        # Sort the lines and output the files
        aAllLines.sort()
        with open(sDayPath, 'w') as f:
            for sLine in aAllLines:
                if re.search('\w', sLine):
                    aLine = self.getRow(sLine)
                    f.write(self.convertRow(aLine) + "\n")
        print("%s - %s - compile log: %s" % (sServer, sDay, sDayPath))

    def processServer(self, sCfId, sServer):
        """Process the complete set of files for a server"""
        print("\nProcess: %s => %s" % (sCfId, sServer))
        sDownloadPath = self.oConfig['logs']['download-path']
        aFiles = {}
        for sFilename in glob.glob(sDownloadPath + '/*'):
            sFile = os.path.basename(sFilename)
            aMatch = re.search('^%s\.(.*?)-\d\d\.' % sCfId, sFile)
            if aMatch is not None:
                sDay = aMatch.group(1)
                if sDay not in aFiles.keys():
                    aFiles[sDay] = []
                aFiles[sDay].append(sFile)

        # Sort the days
        aDays = list(aFiles.keys())
        aDays.sort()

        # Process each day
        for sDay in aDays:
            aFiles[sDay].sort()
            self.processDay(sDay, sServer, aFiles[sDay])

        # self.oPrinter.pprint(aFiles)

    def isValidLog(self, sFile):
        """Determine if file is a valid compressed log"""
        return re.match(r'[A-Z0-9]+\.[0-9\-]+\.[a-z0-9]+\.gz$', sFile)

    def getLogFiles(self):
        """Get a list of log files, in order"""
        aFiles = []
        for sPath in glob.glob(self.oConfig['logs']['download-path'] + '/*'):
            sFile = os.path.basename(sPath)
            if self.isValidLog(sFile):
                aFiles.append(sFile)
        aFiles.sort()
        return aFiles

    def getS3Client(self):
        """Init and get the S3 client"""
        if self.oS3Client is None:
            aAwsConfig = self.oConfig['aws']
            self.oS3Client = boto3.client('s3',
                                          aws_access_key_id=aAwsConfig['access-id'],
                                          aws_secret_access_key=aAwsConfig['access-key'])
        return self.oS3Client

    def getS3Files(self):
        """Get a list of the S3 log files"""
        aS3Config = self.oConfig['s3']
        oList = self.getS3Client().list_objects_v2(
            Bucket=aS3Config['bucket'],
            Prefix=aS3Config['path']
        )
        aFiles = []
        for oItem in oList['Contents']:
            sFile = os.path.basename(oItem['Key'])
            if self.isValidLog(sFile):
                aFiles.append(sFile)
        while oList['IsTruncated']:
            oList = self.getS3Client().list_objects_v2(
                Bucket=aS3Config['bucket'],
                Prefix=aS3Config['path'],
                ContinuationToken=oList['NextContinuationToken']
            )
            for oItem in oList['Contents']:
                sFile = os.path.basename(oItem['Key'])
                if self.isValidLog(sFile):
                    aFiles.append(sFile)

        aFiles.sort()
        return aFiles

    def downloadS3File(self, sFile):
        """Download a specific S3 file to the filesystem"""
        aS3Config = self.oConfig['s3']
        aLogConfig = self.oConfig['logs']

        sS3Path = '%s/%s' % (aS3Config['path'], sFile)
        sFilePath = '%s/%s' % (aLogConfig['download-path'], sFile)
        print("Downloading %s" % sFile)
        self.oS3Client.download_file(aS3Config['bucket'], sS3Path, sFilePath)

    def syncLogDir(self):
        """Synchronize the log files"""

        # Get the files in S3 and filesystem
        aS3Files = self.getS3Files()
        aLogFiles = self.getLogFiles()

        # Get the files that are missing
        aMissing = list(set(aS3Files) - set(aLogFiles))
        aMissing.sort()

        # Copy each of the log files
        for sFile in aMissing:
            self.downloadS3File(sFile)

    def main(self):
        """Primary method"""

        self.initConfig()
        self.syncLogDir()
        aServers = self.oConfig['aliases']
        for sCfId in aServers:
            sServer = aServers[sCfId]
            self.processServer(sCfId, sServer)


if __name__ == "__main__":
    oProcLogs = ProcessLogs()
    oProcLogs.main()
