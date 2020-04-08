#!/bin/sh

echo "Start S3 upload Script....."

declare -a regions=("us-east-1" "ap-south-1")

cd ..\/..\/
for region in "${regions[@]}"
do
    cd quickstart-sumo-logic-log-centralization/scripts/
    bucket_name=sumologiclambdahelper-$region
    echo "Region is $region and Bucket Name is $bucket_name"
    cd ..\/..\/

    aws s3 cp quickstart-sumo-logic-log-centralization/ s3://$bucket_name/quickstart-sumo-logic-log-centralization/ --recursive --exclude '.git/*' --exclude '.idea/*' --acl public-read --profile personal
done

echo "End S3 upload Script....."