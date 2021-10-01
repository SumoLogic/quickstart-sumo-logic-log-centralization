#!/bin/sh

# Dependencies Installation
    # install cfn-nag https://github.com/stelligent/cfn_nag#installation
        # For mac below commands
            # brew install ruby brew-gem
            # brew gem install cfn-nag
    # pip install sumologic-cfn-tester

# sh uploadToS3.sh and provide the bucket details below

bucket_name="aspin2cloudtrail"
declare -a regions=("us-west-1" "us-west-2") #multi regions for cloudtrail and guardduty
repo_dir_path="/home/phunhb/MTT/quickstart-sumo-logic-log-centralization/"
tooling_logging_region="us-west-2"

resource_prefix="org-test-0800" #you should change every when run test.

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
