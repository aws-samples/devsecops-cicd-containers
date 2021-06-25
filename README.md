## AWS DevSecOps Pipeline

Kubernetes DevSecOps pipeline using AWS cloudnative services and open source security vulnerability scanning tools.

![CodeBuild badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoieDJkVmY0VXl2bVRjaFdBYkRzZExTNS9ZTUZVQXE4Sy9GMkh1dk1sOE54VkJKcEowOGdXcnJiZDlGL1RGeXJGUmR5UHlWT1psaks2N1dKbk5qUSt6L1BnPSIsIml2UGFyYW1ldGVyU3BlYyI6InhST3ZVeEZ6bkxLWC9IZG4iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)

This DevSecOps pipeline uses AWS DevOps tools AWS CodeCommit, AWS CodeBuild, and AWS CodePipeline along with other AWS services.  It is highly recommended to fully test the pipeline in lower environments and adjust as needed before deploying to production.

### Build and Test: 

The buildspecs and property files for vulnerability scanning using AWS CodeBuild:
* buildspec-gitsecrets.yaml: buildspec file to perform secret analysis using open source git-secrets.
* buildspec-anchore.yaml: buildspec file to perform SCA/SAST analysis using open source Anchore.
* buildspec-snyk.yaml: buildspec file to perform SCA/SAST analysis using open source Snyk.
* buildspec-ecr-yaml: buildspec file to retrive ECR SCA/SAST analysis results and deploy to staging EKS cluster.
* buildspec-owasp-zap.yaml: buildspec file to perform DAST analysis using open source OWASP ZAP.
* buildspec-prod.yaml: buildspec file to deploy to prod EKS cluster.
* buildspec-owasp-zap.yaml: buildspec file to perform DAST analysis using OWASP Zap.
* dockerfile-wp.dockerfile: sample docker file. Please replace with your Dockerfile.

### Lambda files:

AWS lambda is used to parse the scanning analysis results and post it to AWS Security Hub
* import_findings_security_hub.py: to parse the scanning results, extract the vulnerability details.
* securityhub.py: to post the vulnerability details to AWS Security Hub in ASFF format (AWS Security Finding Format) .

### CloudFormation for Pipeline:

* devsecops-codepipeline-template.yaml: CloudFormation template to deploy the Kubernetes DevSecOps Pipeline 

## Deploying pipeline:

1. Download the CloudFormation template and pipeline code from the GitHub repo.
2. Sign in to your AWS account if you have not done so already. 
3. On the CloudFormation console, choose Create Stack. 
4. Choose the CloudFormation pipeline template. 
5. Choose Next.
6. Under Code, provide the following information:
   i. Code details, such as repository name and the branch to trigger the pipeline.
   ii.The Amazon ECR container image repository name.
7. Under SAST, provide the following information:
   i. Choose the SAST tool (Anchore or Snyk) for code analysis.
   ii.If you select Snyk, provide an API key for Snyk.
8. Under DAST, choose the DAST tool (OWASP ZAP) for dynamic testing and enter the API token, DAST tool URL, and the application URL to run the scan.
9. Under Lambda functions, enter the Lambda function S3 bucket name, filename, and the handler name.
10. For STG EKS cluster, enter the staging EKS cluster name. 
11.	For PRD EKS cluster, enter the production EKS cluster name to which this pipeline deploys the container image. 
12.	Under General, enter the email addresses to receive notifications for approvals and pipeline status changes. 
13.	Choose Next.
14.	Complete the stack.
15.	After the pipeline is deployed, confirm the subscription by choosing the provided link in the email to receive notifications.

The provided CloudFormation template in this post is formatted for AWS GovCloud. If you’re setting this up in a standard Region, you have to adjust the partition name in the CloudFormation template. For example, change ARN values from arn:aws-us-gov to arn:aws. 

## License

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0