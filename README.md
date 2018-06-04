
apt-get update && apt-get install build-essential python3 python3-dev libpam0g-dev python-setuptools -y

mkdir /lib64/security

easy_install pip

pip install virtualenv

virtualenv -p /usr/bin/python3.4 ~/.venv/cauth

source ~/.venv/cauth/bin/activate

pip install -r requirements.txt

auth sufficient /lib64/security/cauth.so