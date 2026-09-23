Remove Windows carriage return
```
sed -i 's/\r$//' .env
```

Install Terraform
```
sudo apt-get update && sudo apt-get install -y gnupg software-properties-common
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null
gpg --no-default-keyring --keyring /usr/share/keyrings/hashicorp-archive-keyring.gpg --fingerprint
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update
sudo apt-get install terraform
```

Verify environment:
```
bash -lc "cd ./ && python3 --version; terraform version; if test -e .env; then echo '.env: present'; else echo '.env: absent'; fi"   
```

Set runtime environment
```
set -a && source .env && set +a
```

Init Terraform
```
terraform init
terraform apply
```

Run webservice
```
python3 web_app.py 8081 &
```
