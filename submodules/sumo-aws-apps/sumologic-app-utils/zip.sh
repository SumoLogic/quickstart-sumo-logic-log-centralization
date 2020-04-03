if [[ -f sumo_app_utils.zip ]]; then
    rm sumo_app_utils.zip
fi

if [[ ! -f sumo_app_utils.zip ]]; then
    echo "copying zip file from sumoloigc-aws-lambda repo."
    curl -LJO https://github.com/SumoLogic/sumologic-aws-lambda/raw/sourabh-aws-observability/sumologic-aws-observability/SumoLogicAWSObservabilityHelper/SumoLogicAWSObservabilityHelper.zip
    mv SumoLogicAWSObservabilityHelper.zip sumo_app_utils.zip
    echo "copy done."
fi