# Install-Nginx-with-Modsecurity-3-OWASP-CRS-on-Ubuntu-24.04
Step 1: Update the System and Install Required Libraries
```
sudo apt update && sudo apt upgrade -y
```
Install libraries  of modsecurity 3.
```
sudo apt install libpcrecpp0v5 -y
sudo apt install gcc make build-essential autoconf automake libtool libcurl4-openssl-dev liblua5.3-dev libfuzzy-dev ssdeep gettext pkg-config libgeoip-dev libyajl-dev doxygen libpcre2-16-0 libpcre2-dev libpcre2-posix3 zlib1g zlib1g-dev -y
```
Install Modsecurity 
```
cd /opt && sudo git clone https://github.com/owasp-modsecurity/ModSecurity.git
cd ModSecurity

sudo git submodule init
sudo git submodule update

sudo ./build.sh
sudo ./configure

sudo make
sudo make install
```
If we success with this installation, we make big move. go on.
Download Modsecurity-nginx Connector

Next, we download modsecurity nginx connector, we will use this later on.
```
cd /opt && sudo git clone https://github.com/owasp-modsecurity/ModSecurity-nginx.git
```
Install Nginx with latest from Ondrej PPA

Ok, we will install nginx from ondrej ppa, we got the latest version of nginx.

First, we need to add repository from ondrej and update our package.
```
sudo add-apt-repository ppa:ondrej/nginx -y
sudo apt update
sudo apt install nginx -y
```
We can enable with systemctl to start nginx when our server up
```
sudo systemctl enable nginx
sudo systemctl status nginx
```
We also need to check our nginx version, to match our nginx build manual later on.
```
sudo nginx -v
nginx version: nginx/1.25.4
```
Download nginx source code

We should download source code that match version on nginx we recently installed.
```
cd /opt && sudo wget https://nginx.org/download/nginx-1.25.4.tar.gz
sudo tar -xzvf nginx-1.25.4.tar.gz
cd nginx-1.25.4
```
after we download, extract and change directory to nginx source. we build nginx with module on modsecurity that we successfully installed above.
```
sudo ./configure --with-compat --add-dynamic-module=/opt/ModSecurity-nginx

sudo make
sudo make modules
```
Next, we copy the modules to nginx modules-enabled, also copy configuration of modsecurity and unicode.
```
sudo cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules-enabled/

sudo cp /opt/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsecurity.conf

sudo cp /opt/ModSecurity/unicode.mapping /etc/nginx/unicode.mapping
```
Enable ModSecurity in nginx.conf

Next, we edit configuration of nginx to load module of modsecurity
```
sudo nano /etc/nginx/nginx.conf
```
add this line to main configuration.
```
load_module /etc/nginx/modules-enabled/ngx_http_modsecurity_module.so;
```
then, we also need to modify the server block to activate modsecurity.
```
sudo nano /etc/nginx/sites-enabled/default

modsecurity on;
modsecurity_rules_file /etc/nginx/modsecurity.conf;
```
and also, edit /etc/nginx/modsecurity.conf to change SecRuleEngine to On.
```
sudo nano /etc/nginx/modsecurity.conf

SecRuleEngine On
```
after that we can our nginx configuration and restart nginx server
```
sudo nginx -t

sudo systemctl restart nginx
```
We can test the nginx server with browser on its public ip address.
Update Rule with CORE RULE SET (CRS)

Now, we need to download core rule set from owasp, owasp crs provide rule to check if the client request has malicious code or not.

We directly download owasp crs to nginx configuration directory.
```
sudo git clone https://github.com/coreruleset/coreruleset.git /etc/nginx/owasp-crs
```
then we copy the configuration.
```
sudo cp /etc/nginx/owasp-crs/crs-setup.conf{.example,}
```
and we need to update our modsecurity configuration to load owasp crs.
```
sudo nano /etc/nginx/modsecurity.conf

Include owasp-crs/crs-setup.conf
Include owasp-crs/rules/*.conf
```
last, we check nginx configuration,
```
sudo nginx -t
```
and restart nginx server.

sudo service nginx restart

Test Modsecurity + Nginx with browser
Try to access to your server and add some shell code on it :
```
https://ip_address/as.php?s=/bin/bash
```
If everything working as expected, forbidden access will show, with code 403. this mean we have success deploy our nginx server with modsecurity module.

To view detail about those error, we can see the log file of the modsecurity.
```
sudo tail -f /var/log/modsec_audit.log
sudo tail -f /var/log/nginx/error.log
```
