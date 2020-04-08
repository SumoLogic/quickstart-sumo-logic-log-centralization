#!/bin/sh

declare -a regions=("us-east-1")
export AWS_PROFILE="personal"
# App to test
export AppName=master
export InstallType=configwithoutenablewithoutsns

# Export Sumo Properties
export Section1aSumoLogicDeployment="us1"
export Section1bSumoLogicAccessID=""
export Section1cSumoLogicAccessKey=""
export Section1dSumoLogicOrganizationId=""
export Section1eSumoLogicResourceRemoveOnDeleteStack=true

for AWS_REGION in "${regions[@]}"
do
    # AWS Quick Start configuration
    export QSS3BucketName="sumologiclambdahelper"-${AWS_REGION}
    export QSS3BucketRegion=${AWS_REGION}

    # Make Everything as No by Default
    export Section2aInstallCloudTrailApp="No"
    export Section2bInstallPCICloudTrailApp="No"
    export Section2cInstallCISFoundationApp="No"
    export Section2dCloudTrailCreateBucket="No"
    export Section2fCloudTrailCreateLogSource="No"
    export Section3aInstallGuardDutyApps="Skip"
    export Section3bInstallGuardDutyBenchMarkApp="No"
    export Section3bGuardDutyCreateHttpLogsSource="No"
    export Section4aInstallVpcApps="Skip"
    export Section4bVpcCreateBucket="No"
    export Section4dVpcCreateS3Source="No"
    export Section5aInstallThreatIntelApp="No"
    export Section6aInstallS3AuditApp="No"
    export Section6bS3AuditCreateBucket="No"
    export Section6dS3AuditCreateS3Source="No"
    export Section7aInstallSecurityHubAuditApp="No"
    export Section7bEnableSecurityHub="No"
    export Section7cSecurityHubCreateBucket="No"
    export Section7eSecurityHubCreateS3Source="No"
    export Section8aInstallWafApp="No"
    export Section8bCreateDeliveryStream="No"
    export Section8cWafCreateBucket="No"
    export Section8eWafCreateS3Source="No"
    export Section9aInstallConfigApp="No"
    export Section9bConfigEnableConfig="No"
    export Section9cConfigCreateSNSTopic="No"
    export Section9eConfigCreateHttpLogsSource="No"
    export Section91aEnableAutoLogging="Skip"
    export Section91bEnableLoggingForExistingResources="No"

    # CloudTrail Config
    export Section2eCloudTrailLogsBucketName="sumologiclambdahelper"-${AWS_REGION}
    export Section2gCloudTrailBucketPathExpression="AWS/CLOUDTRAIL/"${InstallType}
    export Section2hCloudTrailLogsSourceCategoryName="SUMO/CloudTrail/"${InstallType}
    # Guard duty Config
    export Section3cGuardDutyHttpLogsSourceCategoryName="SUMO/GuardDuty/"${InstallType}
    # VPC Config
    export Section4cVpcLogsBucketName="sumologiclambdahelper"-${AWS_REGION}
    export Section4eVpcBucketPathExpression="AWS/VPC/"${InstallType}
    export Section4fVpcLogsSourceCategoryName="SUMO/VPC/"${InstallType}
    # Threat Intel Config
    export Section5bElasticLoadBalancerSourceCategory="SUMO/ALB/"${InstallType}
    # S3 Audit Config
    export Section6cS3AuditLogsBucketName="sumologiclambdahelper"-${AWS_REGION}
    export Section6eS3AuditBucketPathExpression="AWS/S3/"${InstallType}
    export Section6fS3AuditLogsSourceCategoryName="SUMO/S3/"${InstallType}
    # Security Hub Config
    export Section7dSecurityHubLogsBucketName="sumologiclambdahelper"-${AWS_REGION}
    export Section7fSecurityHubBucketPathExpression="AWS/SECURITY/"${InstallType}
    export Section7gSecurityHubLogsSourceCategoryName="SUMO/SECURITY/"${InstallType}
    # WAF Config
    export Section8dWafLogsBucketName="sumologiclambdahelper"-${AWS_REGION}
    export Section8fWafBucketPathExpression="AWS/WAF/"${InstallType}
    export Section8gWafLogsSourceCategoryName="SUMO/WAF/"${InstallType}
    # Config Params
    export Section9dConfigExistingTopicName="SumoSNSTopic-master-configwithoutenable-sumoConfigAppsStack-VVO6QR64OJF2"
    export Section9fConfigHttpLogsSourceCategoryName="SUMO/CONFIG/"${InstallType}
    # Auto Enable
    export Section91cS3LoggingBucketPrefix="S3_AUDIT/"
    export Section91dS3LoggingFilterExpression="lambda"
    export Section91eVPCLoggingBucketPrefix="VPC/"
    export Section91fVPCLoggingFilterExpression=""
    if [[ "${InstallType}" == "cloudtrailall" ]]
    then
        export Section2aInstallCloudTrailApp="Yes"
        export Section2bInstallPCICloudTrailApp="Yes"
        export Section2cInstallCISFoundationApp="Yes"
        export Section2dCloudTrailCreateBucket="Yes"
        export Section2fCloudTrailCreateLogSource="Yes"
    elif [[ "${InstallType}" == "guarddutyall" ]]
    then
        export Section3aInstallGuardDutyApps="Both"
        export Section3bGuardDutyCreateHttpLogsSource="Yes"
    elif [[ "${InstallType}" == "cloudtrailguardutyall" ]]
    then
        export Section2aInstallCloudTrailApp="Yes"
        export Section2bInstallPCICloudTrailApp="Yes"
        export Section2cInstallCISFoundationApp="Yes"
        export Section2dCloudTrailCreateBucket="Yes"
        export Section2fCloudTrailCreateLogSource="Yes"
        export Section3aInstallGuardDutyApps="Both"
        export Section3bGuardDutyCreateHttpLogsSource="Yes"
    elif [[ "${InstallType}" == "cloudtrailwithoutbucket" ]]
    then
        export Section2aInstallCloudTrailApp="Yes"
        export Section2fCloudTrailCreateLogSource="Yes"
    elif [[ "${InstallType}" == "guardutyappsonly" ]]
    then
        export Section3aInstallGuardDutyApps="Both"
    elif [[ "${InstallType}" == "cloudtrailappsonly" ]]
    then
        export Section2aInstallCloudTrailApp="Yes"
        export Section2bInstallPCICloudTrailApp="Yes"
        export Section2cInstallCISFoundationApp="Yes"
    elif [[ "${InstallType}" == "allappsonly" ]]
    then
        export Section2aInstallCloudTrailApp="Yes"
        export Section2bInstallPCICloudTrailApp="Yes"
        export Section2cInstallCISFoundationApp="Yes"
        export Section3aInstallGuardDutyApps="Both"
        export Section3bInstallGuardDutyBenchMarkApp="Yes"
    elif [[ "${InstallType}" == "threatintelapp" ]]
    then
        export Section5aInstallThreatIntelApp="Yes"
    elif [[ "${InstallType}" == "vpcall" ]]
    then
        export Section4aInstallVpcApps="Both"
        export Section4bVpcCreateBucket="Yes"
        export Section4dVpcCreateS3Source="Yes"
    elif [[ "${InstallType}" == "vpcwithoutbucket" ]]
    then
        export Section4aInstallVpcApps="Both"
        export Section4dVpcCreateS3Source="Yes"
    elif [[ "${InstallType}" == "vpcapponly" ]]
    then
        export Section4aInstallVpcApps="VPC"
    elif [[ "${InstallType}" == "s3auditapponly" ]]
    then
        export Section6aInstallS3AuditApp="Yes"
    elif [[ "${InstallType}" == "s3auditwithoutbucket" ]]
    then
        export Section6aInstallS3AuditApp="Yes"
        export Section6dS3AuditCreateS3Source="Yes"
    elif [[ "${InstallType}" == "s3auditall" ]]
    then
        export Section6aInstallS3AuditApp="Yes"
        export Section6bS3AuditCreateBucket="Yes"
        export Section6dS3AuditCreateS3Source="Yes"
    elif [[ "${InstallType}" == "securityhubapponly" ]]
    then
        export Section7aInstallSecurityHubAuditApp="Yes"
    elif [[ "${InstallType}" == "securityhubwithoutbucket" ]]
    then
        export Section7aInstallSecurityHubAuditApp="Yes"
        export Section7bEnableSecurityHub="Yes"
        export Section7eSecurityHubCreateS3Source="Yes"
    elif [[ "${InstallType}" == "securityhuball" ]]
    then
        export Section7aInstallSecurityHubAuditApp="Yes"
        export Section7bEnableSecurityHub="Yes"
        export Section7cSecurityHubCreateBucket="Yes"
        export Section7eSecurityHubCreateS3Source="Yes"
    elif [[ "${InstallType}" == "wafapponly" ]]
    then
        export Section8aInstallWafApp="Yes"
    elif [[ "${InstallType}" == "wafwithoutbucket" ]]
    then
        export Section8aInstallWafApp="Yes"
        export Section8bCreateDeliveryStream="Yes"
        export Section8eWafCreateS3Source="Yes"
    elif [[ "${InstallType}" == "wafall" ]]
    then
        export Section8aInstallWafApp="Yes"
        export Section8bCreateDeliveryStream="Yes"
        export Section8cWafCreateBucket="Yes"
        export Section8eWafCreateS3Source="Yes"
    elif [[ "${InstallType}" == "guarddutyvpc" ]]
    then
        export Section3aInstallGuardDutyApps="GuardDuty"
        export Section4aInstallVpcApps="VPC"
    elif [[ "${InstallType}" == "guarddutybenchmarkvpcpci" ]]
    then
        export Section3aInstallGuardDutyApps="GuardDutyBenchmark"
        export Section4aInstallVpcApps="PCI_VPC"
    elif [[ "${InstallType}" == "guardvpcboth" ]]
    then
        export Section3aInstallGuardDutyApps="Both"
        export Section4aInstallVpcApps="Both"
    elif [[ "${InstallType}" == "s3enablelogs" ]]
    then
        export Section91aEnableAutoLogging="S3"
        export Section91bEnableLoggingForExistingResources="No"
    elif [[ "${InstallType}" == "vpcenablelogs" ]]
    then
        export Section91aEnableAutoLogging="VPC"
        export Section91bEnableLoggingForExistingResources="No"
    elif [[ "${InstallType}" == "enablebothlogs" ]]
    then
        export Section91aEnableAutoLogging="S3_VPC"
        export Section91bEnableLoggingForExistingResources="Yes"
    elif [[ "${InstallType}" == "configall" ]]
    then
        export Section9aInstallConfigApp="Yes"
        export Section9bConfigEnableConfig="Yes"
        export Section9cConfigCreateSNSTopic="Yes"
        export Section9eConfigCreateHttpLogsSource="Yes"
    elif [[ "${InstallType}" == "configwithoutenable" ]]
    then
        export Section9aInstallConfigApp="Yes"
        export Section9cConfigCreateSNSTopic="Yes"
        export Section9eConfigCreateHttpLogsSource="Yes"
    elif [[ "${InstallType}" == "configwithoutenablewithoutsns" ]]
    then
        export Section9aInstallConfigApp="Yes"
        export Section9eConfigCreateHttpLogsSource="Yes"
    else
        echo "No Choice"
    fi

    # Stack Name
    export stackName="${AppName}-${InstallType}"

    aws cloudformation deploy --s3-bucket ${QSS3BucketName} --profile ${AWS_PROFILE} --template-file ./master.template.yaml --region ${AWS_REGION} \
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND CAPABILITY_NAMED_IAM --stack-name ${stackName} \
    --parameter-overrides Section1aSumoLogicDeployment="${Section1aSumoLogicDeployment}" Section1bSumoLogicAccessID="${Section1bSumoLogicAccessID}" \
    Section1cSumoLogicAccessKey="${Section1cSumoLogicAccessKey}" Section1dSumoLogicOrganizationId="${Section1dSumoLogicOrganizationId}" \
    Section1eSumoLogicResourceRemoveOnDeleteStack="${Section1eSumoLogicResourceRemoveOnDeleteStack}" QSS3BucketName="${QSS3BucketName}" QSS3BucketRegion="${QSS3BucketRegion}" \
    Section2aInstallCloudTrailApp="${Section2aInstallCloudTrailApp}" Section2bInstallPCICloudTrailApp="${Section2bInstallPCICloudTrailApp}" \
    Section2cInstallCISFoundationApp="${Section2cInstallCISFoundationApp}" Section2dCloudTrailCreateBucket="${Section2dCloudTrailCreateBucket}" Section2fCloudTrailCreateLogSource="${Section2fCloudTrailCreateLogSource}" \
    Section3aInstallGuardDutyApps="${Section3aInstallGuardDutyApps}" Section3bGuardDutyCreateHttpLogsSource="${Section3bGuardDutyCreateHttpLogsSource}" \
    Section4aInstallVpcApps="${Section4aInstallVpcApps}" Section4bVpcCreateBucket="${Section4bVpcCreateBucket}" \
    Section4dVpcCreateS3Source="${Section4dVpcCreateS3Source}" Section5aInstallThreatIntelApp="${Section5aInstallThreatIntelApp}" Section2eCloudTrailLogsBucketName="${Section2eCloudTrailLogsBucketName}" \
    Section2gCloudTrailBucketPathExpression="${Section2gCloudTrailBucketPathExpression}" Section2hCloudTrailLogsSourceCategoryName="${Section2hCloudTrailLogsSourceCategoryName}" \
    Section3cGuardDutyHttpLogsSourceCategoryName="${Section3cGuardDutyHttpLogsSourceCategoryName}" Section4cVpcLogsBucketName="${Section4cVpcLogsBucketName}" \
    Section4eVpcBucketPathExpression="${Section4eVpcBucketPathExpression}" Section4fVpcLogsSourceCategoryName="${Section4fVpcLogsSourceCategoryName}" \
    Section5bElasticLoadBalancerSourceCategory="${Section5bElasticLoadBalancerSourceCategory}" Section6aInstallS3AuditApp="${Section6aInstallS3AuditApp}" \
    Section6bS3AuditCreateBucket="${Section6bS3AuditCreateBucket}" Section6dS3AuditCreateS3Source="${Section6dS3AuditCreateS3Source}" \
    Section7aInstallSecurityHubAuditApp="${Section7aInstallSecurityHubAuditApp}" Section7bEnableSecurityHub="${Section7bEnableSecurityHub}" \
    Section7cSecurityHubCreateBucket="${Section7cSecurityHubCreateBucket}" Section7eSecurityHubCreateS3Source="${Section7eSecurityHubCreateS3Source}" \
    Section8aInstallWafApp="${Section8aInstallWafApp}" Section8bCreateDeliveryStream="${Section8bCreateDeliveryStream}" Section8cWafCreateBucket="${Section8cWafCreateBucket}" \
    Section8eWafCreateS3Source="${Section8eWafCreateS3Source}" Section6cS3AuditLogsBucketName="${Section6cS3AuditLogsBucketName}" Section6eS3AuditBucketPathExpression="${Section6eS3AuditBucketPathExpression}" \
    Section6fS3AuditLogsSourceCategoryName="${Section6fS3AuditLogsSourceCategoryName}" Section7dSecurityHubLogsBucketName="${Section7dSecurityHubLogsBucketName}" \
    Section7fSecurityHubBucketPathExpression="${Section7fSecurityHubBucketPathExpression}" Section7gSecurityHubLogsSourceCategoryName="${Section7gSecurityHubLogsSourceCategoryName}" \
    Section8dWafLogsBucketName="${Section8dWafLogsBucketName}" Section8fWafBucketPathExpression="${Section8fWafBucketPathExpression}" \
    Section8gWafLogsSourceCategoryName="${Section8gWafLogsSourceCategoryName}" Section9aInstallConfigApp="${Section9aInstallConfigApp}" \
    Section9bConfigEnableConfig="${Section9bConfigEnableConfig}" Section9cConfigCreateSNSTopic="${Section9cConfigCreateSNSTopic}" \
    Section9dConfigExistingTopicName="${Section9dConfigExistingTopicName}" Section9eConfigCreateHttpLogsSource="${Section9eConfigCreateHttpLogsSource}" \
    Section9fConfigHttpLogsSourceCategoryName="${Section9fConfigHttpLogsSourceCategoryName}" Section91aEnableAutoLogging="${Section91aEnableAutoLogging}" \
    Section91bEnableLoggingForExistingResources="${Section91bEnableLoggingForExistingResources}" Section91cS3LoggingBucketPrefix="${Section91cS3LoggingBucketPrefix}" \
    Section91dS3LoggingFilterExpression="${Section91dS3LoggingFilterExpression}" Section91eVPCLoggingBucketPrefix="${Section91eVPCLoggingBucketPrefix}" \
    Section91fVPCLoggingFilterExpression="${Section91fVPCLoggingFilterExpression}"


done