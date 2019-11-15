 #!/usr/bin/env bash

sudo apt-get install -y python3-venv
python3 -m venv venv

# Env variables
echo "" >> ./venv/bin/activate
echo "export SECRET_KEY=\"476677e2-29bc-4ce2-ada2-900f757ed132\"" >> ./venv/bin/activate

source venv/bin/activate
pip3 install -r requirements.txt

sudo apt-get install -y redis-server
sudo systemctl restart redis
