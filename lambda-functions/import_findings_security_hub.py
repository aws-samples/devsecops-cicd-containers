"""
 Imports finding in Security Hub and upload the reports to S3
 Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0
"""

import os
import json
import logging
import boto3
import securityhub
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

FINDING_TITLE = "CodeAnalysis"
FINDING_DESCRIPTION_TEMPLATE = "Summarized report of code scan with {0}"
FINDING_TYPE_TEMPLATE = "{0} code scan"
BEST_PRACTICES_CFN = "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html"
BEST_PRACTICES_OWASP = "https://owasp.org/www-project-top-ten/"
report_url = "https://aws.amazon.com"
vul_level = "LOW"

def process_message(event):
    """ Process Lambda Event """
    print('#### complete event details')
    print(event)
    if event['messageType'] == 'CodeScanReport':
        account_id = boto3.client('sts').get_caller_identity().get('Account')
        region = os.environ['AWS_REGION']
        created_at = event['createdAt']
        source_repository = event['source_repository']
        source_branch = event['source_branch']
        source_commitid = event['source_commitid']
        build_id = event['build_id']
        report_type = event['reportType']
        finding_type = FINDING_TYPE_TEMPLATE.format(report_type)
        generator_id = f"{report_type.lower()}-{source_repository}-{source_branch}"
        vul_level = "LOW"
        ##upload to S3 bucket.
        s3 = boto3.client('s3')
        s3bucket = "pipeline-artifact-bucket-" + account_id
        key = f"reports/{event['reportType']}/{build_id}-{created_at}.json"
        s3.put_object(Bucket=s3bucket, Body=json.dumps(event), Key=key, ServerSideEncryption='aws:kms')
        report_url = f"https://s3.console.aws.amazon.com/s3/object/{s3bucket}/{key}?region={region}"

        if ( event['reportType'] == 'ECR' ):
            FINDING_TITLE = "AWS ECR StaticCode Analysis"
            severity = 50            
            vuln_ct = event['report']['imageScanFindings']['findings']
            vuln_count = len(vuln_ct)
            count = 1
            title_list = []
            for i in range(vuln_count):
                severity = event['report']['imageScanFindings']['findings'][i]['severity']
                name = event['report']['imageScanFindings']['findings'][i]['name']
                url = event['report']['imageScanFindings']['findings'][i]['uri']        
                if severity not in ['Negligible', 'Unknown', 'INFORMATIONAL']:
                    normalized_severity =  assign_normalized_severity(severity)
                    finding_description = f"{count}---Name:{name}---Sevierity:{severity}---URL:{url}"
                    finding_id = f"{count}-{report_type.lower()}-{build_id}"
                    created_at = datetime.now(timezone.utc).isoformat()
                    count += 1
                    securityhub.import_finding_to_sh(count, account_id, region, created_at, source_repository, source_branch, source_commitid, build_id, report_url, finding_id, generator_id, normalized_severity, severity, finding_type, FINDING_TITLE, finding_description, BEST_PRACTICES_CFN)               
                    
        elif ( event['reportType'] == 'SNYK' ):
            FINDING_TITLE = "Snyk StaticCode Analysis" 
            severity = 50            
            vuln_ct = event['report']['vulnerabilities']
            vuln_count = len(vuln_ct)
            print(f"alert count is {vuln_count}")
            count = 1
            title_list = []
            for i in range(vuln_count):
                title = event['report']['vulnerabilities'][i]['title']
                if title not in title_list:
                    title_list.append(title)
                    severity = event['report']['vulnerabilities'][i]['severity']
                    packageName = event['report']['vulnerabilities'][i]['packageName']
                    cvssScore = event['report']['vulnerabilities'][i]['cvssScore']
                    nvdSeverity = event['report']['vulnerabilities'][i]['nvdSeverity']        
                    if severity not in ['Negligible', 'Unknown']:
                        normalized_severity =  assign_normalized_severity(severity)
                        finding_description = f"{count}---Title:{title}---Package:{packageName}---Sevierity:{severity}---CVSSv3_Score:{cvssScore}"
                        finding_id = f"{count}-{report_type.lower()}-{build_id}"
                        created_at = datetime.now(timezone.utc).isoformat()
                        count += 1
                        securityhub.import_finding_to_sh(count, account_id, region, created_at, source_repository, source_branch, source_commitid, build_id, report_url, finding_id, generator_id, normalized_severity, severity, finding_type, FINDING_TITLE, finding_description, BEST_PRACTICES_CFN)               

        elif ( event['reportType'] == 'ANCHORE' ): 
            FINDING_TITLE = "Anchore StaticCode Analysis" 
            severity = 50            
            vuln_ct = event['report']['vulnerabilities']
            vuln_count = len(vuln_ct)
            print(f"alert count is {vuln_count}")
            count = 1
            for i in range(vuln_count):
                severity = event['report']['vulnerabilities'][i]['severity']
                vuln = event['report']['vulnerabilities'][i]['vuln']
                url = event['report']['vulnerabilities'][i]['url']
                feed_group = event['report']['vulnerabilities'][i]['feed_group']
                package = event['report']['vulnerabilities'][i]['package']
                if severity not in ['Negligible', 'Unknown']:
                    normalized_severity =  assign_normalized_severity(severity)
                    finding_description = f"{count}---Package:{package}--- Vulnerability:{vuln}---Details:{url}"
                    print(f"finding description is: {finding_description}")
                    finding_id = f"{count}-{report_type.lower()}-{build_id}"
                    created_at = datetime.now(timezone.utc).isoformat()
                    count += 1
                    securityhub.import_finding_to_sh(count, account_id, region, created_at, source_repository, source_branch, source_commitid, build_id, report_url, finding_id, generator_id, normalized_severity, severity, finding_type, FINDING_TITLE, finding_description, BEST_PRACTICES_CFN)               
               
        elif event['reportType'] == 'OWASP-Zap':  
            severity = 50
            vul_level = "LOW"
            FINDING_TITLE = "OWASP ZAP DynamicCode Analysis"
            alert_ct = event['report']['site'][0]['alerts']
            alert_count = len(alert_ct)
            for alertno in range(alert_count):
                risk_desc = event['report']['site'][0]['alerts'][alertno]['riskdesc']
                severity = risk_desc[0:3]
                normalized_severity =  assign_normalized_severity(severity)                                        
                instances = len(event['report']['site'][0]['alerts'][alertno]['instances'])
                finding_description = f"{alertno}-Vulerability:{event['report']['site'][0]['alerts'][alertno]['alert']}-Total occurances of this issue:{instances}"
                finding_id = f"{alertno}-{report_type.lower()}-{build_id}"
                created_at = datetime.now(timezone.utc).isoformat()
                securityhub.import_finding_to_sh(alertno, account_id, region, created_at, source_repository, source_branch, source_commitid, build_id, report_url, finding_id, generator_id, normalized_severity, severity, finding_type, FINDING_TITLE, finding_description, BEST_PRACTICES_OWASP)
        else:
            print("Invalid report type was provided")        
        return vul_level        
    else:
        logger.error("Report type not supported:")

def assign_normalized_severity(severity):
    if severity in ['MAJOR', 'MEDIUM', 'Med', 'Medium', 'medium']:
        normalized_severity = 70
        vul_level = "NOTLOW"
    elif severity in ['CRITICAL', 'BLOCKER', 'MAJOR', 'HIGH', 'Hig', 'High', 'high']:
        normalized_severity = 90
        vul_level = "NOTLOW"
    elif severity in ['LOW', 'Low', 'Inf', 'low', 'INFORMATIONAL']:
        normalized_severity = 20
        vul_level = "LOW"
    else:
        normalized_severity= 20
    return normalized_severity

def lambda_handler(event, context):
    """ Lambda entrypoint """
    try:
        logger.info("Starting function")
        return process_message(event)
    except Exception as error:
        logger.error("Error {}".format(error))
        raise

