if [ ! -f sumo_app_utils.zip ]; then
    echo "creating zip file"
    mkdir python
    cd python
    pip install  crhelper -t .
    pip install requests -t .
    cp -v ../src/* .
    zip -r ../cloudwatchevents.zip .
    cd ..
    rm -r python
fi