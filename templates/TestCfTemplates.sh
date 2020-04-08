#!/bin/sh

declare -a regions=("us-east-1")
export AWS_PROFILE="personal"
# App to test
export AppName=master
export InstallType=wafall

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
    export Section3aInstallGuardDutyApp="No"
    export Section3bInstallGuardDutyBenchMarkApp="No"
    export Section3cGuardDutyCreateHttpLogsSource="No"
    export Section4aInstallVpcApp="No"
    export Section4bInstallPCIVpcApp="No"
    export Section4cVpcCreateBucket="No"
    export Section4eVpcCreateS3Source="No"
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

    # CloudTrail Config
    export Section2eCloudTrailLogsBucketName="sumologiclambdahelper"-${AWS_REGION}
    export Section2gCloudTrailBucketPathExpression="AWS/CLOUDTRAIL/"${InstallType}
    export Section2hCloudTrailLogsSourceCategoryName="SUMO/CloudTrail/"${InstallType}
    # Guard duty Config
    export Section3dGuardDutyHttpLogsSourceCategoryName="SUMO/GuardDuty/"${InstallType}
    # VPC Config
    export Section4dVpcLogsBucketName="sumologiclambdahelper"-${AWS_REGION}
    export Section4fVpcBucketPathExpression="AWS/VPC/"${InstallType}
    export Section4gVpcLogsSourceCategoryName="SUMO/VPC/"${InstallType}
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

    if [[ "${InstallType}" == "cloudtrailall" ]]
    then
        export Section2aInstallCloudTrailApp="Yes"
        export Section2bInstallPCICloudTrailApp="Yes"
        export Section2cInstallCISFoundationApp="Yes"
        export Section2dCloudTrailCreateBucket="Yes"
        export Section2fCloudTrailCreateLogSource="Yes"
    elif [[ "${InstallType}" == "guarddutyall" ]]
    then
        export Section3aInstallGuardDutyApp="Yes"
        export Section3bInstallGuardDutyBenchMarkApp="Yes"
        export Section3cGuardDutyCreateHttpLogsSource="Yes"
    elif [[ "${InstallType}" == "cloudtrailguardutyall" ]]
    then
        export Section2aInstallCloudTrailApp="Yes"
        export Section2bInstallPCICloudTrailApp="Yes"
        export Section2cInstallCISFoundationApp="Yes"
        export Section2dCloudTrailCreateBucket="Yes"
        export Section2fCloudTrailCreateLogSource="Yes"
        export Section3aInstallGuardDutyApp="Yes"
        export Section3bInstallGuardDutyBenchMarkApp="Yes"
        export Section3cGuardDutyCreateHttpLogsSource="Yes"
    elif [[ "${InstallType}" == "cloudtrailwithoutbucket" ]]
    then
        export Section2aInstallCloudTrailApp="Yes"
        export Section2fCloudTrailCreateLogSource="Yes"
    elif [[ "${InstallType}" == "guardutyappsonly" ]]
    then
        export Section3aInstallGuardDutyApp="Yes"
        export Section3bInstallGuardDutyBenchMarkApp="Yes"
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
        export Section3aInstallGuardDutyApp="Yes"
        export Section3bInstallGuardDutyBenchMarkApp="Yes"
    elif [[ "${InstallType}" == "threatintelapp" ]]
    then
        export Section5aInstallThreatIntelApp="Yes"
    elif [[ "${InstallType}" == "vpcall" ]]
    then
        export Section4aInstallVpcApp="Yes"
        export Section4bInstallPCIVpcApp="Yes"
        export Section4cVpcCreateBucket="Yes"
        export Section4eVpcCreateS3Source="Yes"
    elif [[ "${InstallType}" == "vpcwithoutbucket" ]]
    then
        export Section4aInstallVpcApp="Yes"
        export Section4eVpcCreateS3Source="Yes"
    elif [[ "${InstallType}" == "vpcapponly" ]]
    then
        export Section4aInstallVpcApp="Yes"
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
    else
        echo "No Choice"
    fi

    # Stack Name
    export stackName="${AppName}-${InstallType}"

    aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./master.template.yaml --region ${AWS_REGION} \
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND CAPABILITY_NAMED_IAM --stack-name ${stackName} \
    --parameter-overrides Section1aSumoLogicDeployment="${Section1aSumoLogicDeployment}" Section1bSumoLogicAccessID="${Section1bSumoLogicAccessID}" \
    Section1cSumoLogicAccessKey="${Section1cSumoLogicAccessKey}" Section1dSumoLogicOrganizationId="${Section1dSumoLogicOrganizationId}" \
    Section1eSumoLogicResourceRemoveOnDeleteStack="${Section1eSumoLogicResourceRemoveOnDeleteStack}" QSS3BucketName="${QSS3BucketName}" QSS3BucketRegion="${QSS3BucketRegion}" \
    Section2aInstallCloudTrailApp="${Section2aInstallCloudTrailApp}" Section2bInstallPCICloudTrailApp="${Section2bInstallPCICloudTrailApp}" \
    Section2cInstallCISFoundationApp="${Section2cInstallCISFoundationApp}" Section2dCloudTrailCreateBucket="${Section2dCloudTrailCreateBucket}" Section2fCloudTrailCreateLogSource="${Section2fCloudTrailCreateLogSource}" \
    Section3aInstallGuardDutyApp="${Section3aInstallGuardDutyApp}" Section3bInstallGuardDutyBenchMarkApp="${Section3bInstallGuardDutyBenchMarkApp}" Section3cGuardDutyCreateHttpLogsSource="${Section3cGuardDutyCreateHttpLogsSource}" \
    Section4aInstallVpcApp="${Section4aInstallVpcApp}" Section4bInstallPCIVpcApp="${Section4bInstallPCIVpcApp}" Section4cVpcCreateBucket="${Section4cVpcCreateBucket}" \
    Section4eVpcCreateS3Source="${Section4eVpcCreateS3Source}" Section5aInstallThreatIntelApp="${Section5aInstallThreatIntelApp}" Section2eCloudTrailLogsBucketName="${Section2eCloudTrailLogsBucketName}" \
    Section2gCloudTrailBucketPathExpression="${Section2gCloudTrailBucketPathExpression}" Section2hCloudTrailLogsSourceCategoryName="${Section2hCloudTrailLogsSourceCategoryName}" \
    Section3dGuardDutyHttpLogsSourceCategoryName="${Section3dGuardDutyHttpLogsSourceCategoryName}" Section4dVpcLogsBucketName="${Section4dVpcLogsBucketName}" \
    Section4fVpcBucketPathExpression="${Section4fVpcBucketPathExpression}" Section4gVpcLogsSourceCategoryName="${Section4gVpcLogsSourceCategoryName}" \
    Section5bElasticLoadBalancerSourceCategory="${Section5bElasticLoadBalancerSourceCategory}" Section6aInstallS3AuditApp="${Section6aInstallS3AuditApp}" \
    Section6bS3AuditCreateBucket="${Section6bS3AuditCreateBucket}" Section6dS3AuditCreateS3Source="${Section6dS3AuditCreateS3Source}" \
    Section7aInstallSecurityHubAuditApp="${Section7aInstallSecurityHubAuditApp}" Section7bEnableSecurityHub="${Section7bEnableSecurityHub}" \
    Section7cSecurityHubCreateBucket="${Section7cSecurityHubCreateBucket}" Section7eSecurityHubCreateS3Source="${Section7eSecurityHubCreateS3Source}" \
    Section8aInstallWafApp="${Section8aInstallWafApp}" Section8bCreateDeliveryStream="${Section8bCreateDeliveryStream}" Section8cWafCreateBucket="${Section8cWafCreateBucket}" \
    Section8eWafCreateS3Source="${Section8eWafCreateS3Source}" Section6cS3AuditLogsBucketName="${Section6cS3AuditLogsBucketName}" Section6eS3AuditBucketPathExpression="${Section6eS3AuditBucketPathExpression}" \
    Section6fS3AuditLogsSourceCategoryName="${Section6fS3AuditLogsSourceCategoryName}" Section7dSecurityHubLogsBucketName="${Section7dSecurityHubLogsBucketName}" \
    Section7fSecurityHubBucketPathExpression="${Section7fSecurityHubBucketPathExpression}" Section7gSecurityHubLogsSourceCategoryName="${Section7gSecurityHubLogsSourceCategoryName}" \
    Section8dWafLogsBucketName="${Section8dWafLogsBucketName}" Section8fWafBucketPathExpression="${Section8fWafBucketPathExpression}" \
    Section8gWafLogsSourceCategoryName="${Section8gWafLogsSourceCategoryName}"


done