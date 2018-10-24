# ========= Ubuntu 16.04
# ======================

# ==== Fixing locales problem
echo "LANG=en_US.UTF-8" | sudo tee -a /etc/default/locale > /dev/null
echo "LC_ALL=en_US.UTF-8" | sudo tee -a /etc/default/locale > /dev/null
source /etc/default/locale

# ==== Installing Protobuf
pip install protobuf

# ==== Installing dyscobess
git clone https://github.com/fabricioufmt/dyscobess
cd dyscobess
sudo apt-get install -y software-properties-common
sudo apt-add-repository -y ppa:ansible/ansible
sudo apt-get update
sudo apt-get install -y ansible
ansible-playbook -K -t package -i localhost, -c local env/bess.yml

