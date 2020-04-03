#!/bin/bash

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppTemplateName="cloudtrail"
export AppName="cloudtrail"
export InstallTypes=("appexistingS3")

for InstallType in "${InstallTypes[@]}"
do
    export CloudTrailLogsBucketName="${AppName}-${InstallType}-qwerty"
    export QSS3BucketName="sumologiclambdahelper"
    export QSS3BucketRegion="us-east-1"

    if [[ "${InstallType}" == "all" ]]
    then
        export InstallApp="Yes"
        export CreateCloudTrailBucket="Yes"
        export CreateCloudTrailLogSource="Yes"
    elif [[ "${InstallType}" == "onlyapp" ]]
    then
        export InstallApp="Yes"
        export CreateCloudTrailBucket="No"
        export CreateCloudTrailLogSource="No"
    elif [[ "${InstallType}" == "appexistingS3" ]]
    then
        export InstallApp="Yes"
        export CreateCloudTrailBucket="No"
        export CreateCloudTrailLogSource="Yes"
        export CloudTrailLogsBucketName="lambda-all-randmomstring"
    elif [[ "${InstallType}" == "onlysource" ]]
    then
        export InstallApp="No"
        export CreateCloudTrailBucket="Yes"
        export CreateCloudTrailLogSource="Yes"
    else
        echo "No Choice"
    fi

    # Export Sumo Properties
    export SumoAccessID=""
    export SumoAccessKey=""
    export SumoOrganizationId=""
    export SumoDeployment="us1"
    export RemoveSumoResourcesOnDeleteStack=true

    # Export Collector Name
    export CollectorName="AWS-Sourabh-Collector-${AppName}-${InstallType}"

    # Export CloudTrail Logs Details
    export CloudTrailBucketPathExpression="*"
    export CloudTrailLogsSourceName="AWS-CloudTrail-${AppName}-${InstallType}-Source"
    export CloudTrailLogsSourceCategoryName="AWS/CloudTrail/${AppName}/${InstallType}/Logs"

    export template_file="${AppTemplateName}.template.yaml"

    aws cloudformation deploy --profile ${AWS_PROFILE} --region ${AWS_REGION} --template-file ./cloudtrail.template.yaml \
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name "${AppName}-${InstallType}" \
    --parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
    SumoOrganizationId="${SumoOrganizationId}" RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
    CollectorName="${CollectorName}" CloudTrailLogsBucketName="${CloudTrailLogsBucketName}" CloudTrailBucketPathExpression="${CloudTrailBucketPathExpression}" \
    CloudTrailLogsSourceName="${CloudTrailLogsSourceName}" CloudTrailLogsSourceCategoryName="${CloudTrailLogsSourceCategoryName}" \
    CreateCloudTrailBucket="${CreateCloudTrailBucket}" CreateCloudTrailLogSource="${CreateCloudTrailLogSource}" \
    QSS3BucketName="${QSS3BucketName}" QSS3BucketRegion="${QSS3BucketRegion}" InstallApp="${InstallApp}"

done

echo "All Installation Complete for ${AppName}"