# Nginx-with-Modsecurity-3-OWASP-CRS-on-Ubuntu-24.04-installation
Step 1: Update the System and Install Required Libraries
```
sudo apt update && sudo apt upgrade -y
```
Install Required Libraries for ModSecurity 3:
```
sudo apt install libpcrecpp0v5 -y
sudo apt install gcc make build-essential autoconf automake libtool libcurl4-openssl-dev liblua5.3-dev libfuzzy-dev ssdeep gettext pkg-config libgeoip-dev libyajl-dev doxygen libpcre2-16-0 libpcre2-dev libpcre2-posix3 zlib1g zlib1g-dev -y
```
Install ModSecurity 3
Clone ModSecurity Repository:
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
Download ModSecurity-Nginx Connector

Next, download the ModSecurity-Nginx connector to integrate ModSecurity with Nginx.
```
cd /opt && sudo git clone https://github.com/owasp-modsecurity/ModSecurity-nginx.git
```
Install Nginx

We'll install the latest version of Nginx from the Ondrej PPA repository.
Add Repository and Install Nginx:
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
nginx version: nginx/1.26.3

```
Download nginx source code

We should download source code that match version on nginx we recently installed.
```
cd /opt && sudo wget https://nginx.org/download/nginx-1.26.3.tar.gz
sudo tar -xzvf nginx-1.26.3.tar.gz
cd nginx-1.26.3
```
Build Nginx with ModSecurity

Configure and build Nginx with ModSecurity support.
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
 Download OWASP CRS (Core Rule Set)

Download the OWASP CRS to protect the web application.
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


To test if ModSecurity is working, try accessing the server and adding a shell command to the URL, e.g.,:
```
https://ip_address/as.php?s=/bin/bash
```
If ModSecurity is functioning, a 403 Forbidden error will be shown, indicating the request was blocked.
View ModSecurity Logs:

You can view detailed logs of ModSecurity for blocked requests:
```
sudo tail -f /var/log/modsec_audit.log
sudo tail -f /var/log/nginx/error.log
```

To block the IP address 103.101.15.218 using ModSecurity, follow these steps:
Step-by-Step Instructions:

    Edit the ModSecurity Configuration File:

        The ModSecurity configuration file is typically located at /etc/nginx/modsecurity.conf. Open this file in a text editor.
```
sudo nano /etc/nginx/modsecurity.conf
```
Add the IP Blocking Rule:

    Add the following rule to block the IP 103.101.15.218. Place it anywhere in the file (ideally in a section where you're managing custom rules, like at the end of the file).
```
SecRule REMOTE_ADDR "@ipMatch 103.101.15.218" \
    "id:1001,deny,status:403,msg:'Blocking IP 103.101.15.218',severity:2"
```
Explanation:

    SecRule: The ModSecurity rule directive.

    REMOTE_ADDR: Refers to the client's IP address.

    @ipMatch: The operator to match the specified IP.

    103.101.15.218: The IP address you want to block.

    id:1001: A unique rule ID. Ensure this number is not used elsewhere.

    deny: The action to take, which is to deny the request.

    status:403: The HTTP response status code for forbidden access.

    msg:'Blocking IP 103.101.15.218': A custom message that will be logged.

    severity:2: The severity level for the rule.
