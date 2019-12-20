if [ ! -f sumo_app_utils.zip ]; then
    echo "creating zip file"
    mkdir python
    cd python
    pip install  crhelper -t .
    pip install requests -t .
    cp -v ../src/*.py .
    zip -r ../sumo_app_utils.zip .
    cd ..
    rm -r python
fi