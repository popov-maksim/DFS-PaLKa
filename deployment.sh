 #!/usr/bin/env bash

sudo apt-get install -y python3-venv
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

sudo apt-get install -y redis-server
sudo systemctl restart redis
