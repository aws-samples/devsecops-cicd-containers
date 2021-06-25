## AWS DevSecOps Pipeline

Kubernetes DevSecOps pipeline using AWS cloudnative services and open source security vulnerability scanning tools.

![CodeBuild badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoieDJkVmY0VXl2bVRjaFdBYkRzZExTNS9ZTUZVQXE4Sy9GMkh1dk1sOE54VkJKcEowOGdXcnJiZDlGL1RGeXJGUmR5UHlWT1psaks2N1dKbk5qUSt6L1BnPSIsIml2UGFyYW1ldGVyU3BlYyI6InhST3ZVeEZ6bkxLWC9IZG4iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)

This DevSecOps pipeline uses AWS DevOps tools AWS CodeCommit, AWS CodeBuild, and AWS CodePipeline along with other AWS services.  It is highly recommended to fully test the pipeline in lower environments and adjust as needed before deploying to production.

### Build and Test: 

The buildspecs and property files for vulnerability scanning using AWS CodeBuild:
* buildspec-gitsecrets.yml: buildspec file to perform secret analysis using open source git-secrets.
* buildspec-anchore.yml: buildspec file to perform SCA/SAST analysis using open source Anchore.
* buildspec-snyk.yml: buildspec file to perform SCA/SAST analysis using open source Snyk.
* buildspec-ecr-yml: buildspec file to retrive ECR SCA/SAST analysis results and deploy to staging EKS cluster.
* buildspec-owasp-zap.yml: buildspec file to perform DAST analysis using open source OWASP ZAP.
* buildspec-prod.yml: buildspec file to deploy to prod EKS cluster.
* buildspec-owasp-zap.yml: buildspec file to perform DAST analysis using OWASP Zap.
* dockerfile-wp.dockerfile: sample docker file. Please replace with your Dockerfile.

### Lambda files:

AWS lambda is used to parse the scanning analysis results and post it to AWS Security Hub
* import_findings_security_hub.py: to parse the scanning results, extract the vulnerability details.
* securityhub.py: to post the vulnerability details to AWS Security Hub in ASFF format (AWS Security Finding Format).

### CloudFormation for Pipeline:

* devsecops-codepipeline-template.yaml: CloudFormation template to deploy the Kubernetes DevSecOps Pipeline 

## Prerequisites

1. An EKS cluster environment with your application deployed. In this post, we use PHP WordPress as a sample application, but you can use any other application.
2. Sysdig Falco installed on an EKS cluster. Sysdig Falco captures events on the EKS cluster and sends those events to CloudWatch using AWS FireLens. For implementation instructions, see Implementing Runtime security in Amazon EKS using CNCF Falco. This step is required only if you need to implement RASP in the software factory.
3. A CodeCommit repo with your application code and a Dockerfile. For more information, see Create an AWS CodeCommit repository.
4. An Amazon ECR repo to store container images and scan for vulnerabilities. Enable vulnerability scanning on image push in Amazon ECR. You can enable or disable the automatic scanning on image push via the Amazon ECR
5. The provided buildspec-*.yml files for git-secrets, Anchore, Snyk, Amazon ECR, OWASP ZAP, and your Kubernetes deployment .yml files uploaded to the root of the application code repository. Please update the Kubernetes (kubectl) commands in the buildspec files as needed.
6. A Snyk API key if you use Snyk as a SAST tool.
7. The Lambda function uploaded to an S3 bucket. We use this function to parse the scan reports and post the results to Security Hub.
8. An OWASP ZAP URL and generated API key for dynamic web scanning.
9. An application web URL to run the DAST testing.
10. An email address to receive approval notifications for deployment, pipeline change notifications, and CloudTrail events.
11. AWS Config and Security Hub services enabled. For instructions, see Managing the Configuration Recorder and Enabling Security Hub manually, respectively.

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

## Cleanup

1. Delete the EKS cluster.
2. Delete the S3 bucket.
3. Delete the CodeCommit repo.
4. Delete the Amazon ECR repo.
5. Disable Security Hub.
6. Disable AWS Config.
7. Delete the pipeline CloudFormation stack.

## License

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0