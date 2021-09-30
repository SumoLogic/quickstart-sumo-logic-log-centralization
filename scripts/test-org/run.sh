#!/bin/sh

# Dependencies Installation
    # install cfn-nag https://github.com/stelligent/cfn_nag#installation
        # For mac below commands
            # brew install ruby brew-gem
            # brew gem install cfn-nag
    # pip install sumologic-cfn-tester

# sh uploadToS3.sh and provide the bucket details below
region_stack="us-east-1"    #region where create stack
bucket_name="aspin2cloudtrail"
declare -a regions=("us-east-1" "us-east-2") #multi regions for cloudtrail and guardduty
repo_dir_path="/media/truecrypt1/quickstart-sumo-logic-log-centralization/"
tooling_logging_region="us-east-2"

resource_prefix="org-test-1748"

aws s3 cp "$repo_dir_path" s3://${bucket_name}-${region_stack}/quickstart-sumo-logic-log-centralization/ --recursive --exclude '.git/*' --exclude '.idea/*' --exclude 'docs/*' --exclude 'scripts/*' --acl public-read

for region in "${regions[@]}"
do
   aws s3 cp "$repo_dir_path" s3://${bucket_name}-${region}/quickstart-sumo-logic-log-centralization/ --recursive --exclude '.git/*' --exclude '.idea/*' --exclude 'docs/*' --exclude 'scripts/*' --acl public-read
done

regions_string=$( IFS=$','; echo "${regions[*]}" )


export AWS_PROFILE="default"
export ENTERPRISE_ACCESS_ID=""
export ENTERPRISE_ACCESS_KEY=""
export ENTERPRISE_DEPLOYMENT="us2"
export ENTERPRISE_ORG_ID=""
export TOOLING_ACCOUNT_ID=""
export LOGGING_ACCOUNT_ID=""
export TOOLING_LOGGING_REGION="$tooling_logging_region"
export ORG_ID=""
export TOOLING_OU=""
export LOGGING_OU=""
export REGION_STACK="$region_stack"
export QSS3BucketName="$bucket_name"
export CLOUDTRAIL_GUARDDUTY_REGIONS="${regions_string}"
export RESOURCE_PREFIX="${resource_prefix}"

sumocfntester -f test.yaml -d true
