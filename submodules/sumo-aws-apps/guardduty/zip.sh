if [[ -f cloudwatchevents.zip ]]; then
    rm cloudwatchevents.zip
fi

if [[ ! -f cloudwatchevents.zip ]]; then
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