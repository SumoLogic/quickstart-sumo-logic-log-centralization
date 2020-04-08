#!/bin/sh

declare -a regions=("us-east-1")
export AWS_PROFILE="personal"
# App to test
export AppName=master
export InstallType=vpcall

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

    # CloudTrail Config
    export Section2eCloudTrailLogsBucketName="sumologiclambdahelper"-${AWS_REGION}
    export Section2gCloudTrailBucketPathExpression="AWS/LOGS/"${InstallType}
    export Section2hCloudTrailLogsSourceCategoryName="SUMO/CloudTrail/"${InstallType}
    # Guard duty Config
    export Section3dGuardDutyHttpLogsSourceCategoryName="SUMO/GuardDuty/"${InstallType}
    # VPC Config
    export Section4dVpcLogsBucketName="sumologiclambdahelper"-${AWS_REGION}
    export Section4fVpcBucketPathExpression="AWS/LOGS/"${InstallType}
    export Section4gVpcLogsSourceCategoryName="SUMO/VPC/"${InstallType}
    # Threat Intel Config
    export Section5bElasticLoadBalancerSourceCategory="SUMO/ALB/"${InstallType}

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
    else
        echo "No Choice"
    fi

    # Stack Name
    export stackName="${AppName}-${InstallType}"

    aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./master.template.yaml --region ${AWS_REGION} \
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
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
    Section5bElasticLoadBalancerSourceCategory="${Section5bElasticLoadBalancerSourceCategory}"

done