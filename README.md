# Nginx

Class: Web Server
Type: Recap
Reviewed: Yes
Created by: ahmed rizk

```groovy

# check nginx configurations 
nginx -V
```

- Nginx can communicate with a backend via **TCP or Unix Socket**
- Location blocks use **modifiers** to change how incoming requests are matched
    - **order of importance:** 1) exact 2) preferential prefix 3) regex 4) prefix

/etc/nginx/nginx.config

```groovy
events {}

http {

	# to read css file and other types and other
  # we map it to the existing file "created by nginx"
  
	include mime.types;

	# create a server
        # listen to port 80
        # set ipaddress/domain
        # search on the path in /sites/demo
        # after any change -> systemctl reload nginx
        # set a prefix location -> ip/greet , ip/greetings 
        # set a exact location -> ip/greet ONLY

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

    # Preferential Prefix match
    location ^~ /Greet2 {
      return 200 'Hello from NGINX "/greet" location.';
    }

    # # Exact match
    # location = /greet {
    #   return 200 'Hello from NGINX "/greet" location - EXACT MATCH.';
    # }

    # # REGEX match - case sensitive
    # location ~ /greet[0-9] {
    #   return 200 'Hello from NGINX "/greet" location - REGEX MATCH.';
    # }

    # REGEX match - case insensitive
    location ~* /greet[0-9] {
      return 200 'Hello from NGINX "/greet" location - REGEX MATCH INSENSITIVE.';
    }
  }
}
```

check predefined variables:

[Alphabetical index of variables](https://nginx.org/en/docs/varindex.html)

Example:

- create location /is_monday
    - create variable mon = No
    - check the today’s day using predefine variable -> date_local
    - if it is monday make mon → yes
- create location /inspect
    - get all predefined host with url and args

```groovy
events {}

http {

  include mime.types;

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

		# set variable
    set $mon 'No';

    # Check if weekend
    if ( $date_local ~ 'Monday' ) {
      set $mon 'Yes';
    }

		location /is_monday {
      return 200 $mon;
    }

		location /inspect {
			return 200 "$host\n$url\n$args"
		}
    
  }
}
```

What is the difference between rewrite and redirect in Nginx?

- rewrite → moves the request internally by creating a new request to the client
- redirect → redirect the existing request to the client

Example:

- rewrite /user/ to /greet:
    - in case it /user/AnyName → appear “Hello User”
    - in case it /user/john→ appear “Hello John”

```groovy
events {}

http {

  include mime.types;

  server {

    listen 80;
    server_name 167.99.93.26;
    root /sites/demo;
		
	  rewrite ^/user/(\w+) /greet/$1 ;
    
    location /greet {

      return 200 "Hello User";
    }

    location = /greet/john {
      return 200 "Hello John";
    }
  }
}
```

name location: for calling → using @

try_files: check the root directory set in nginx.config:

- if they existed he will go there if not it will check the next
- the last parameter is for the rewrite option

Example:

- using try_files:
    - check if there “cat.png” in “/sites/demo”
    - if not check the following “/greet” → which is not existed in the /sites/demo even if there is a location created to it → would be neglected
    - in case of there are nothing to find it will rewrite to the last parameter ONLY “friendly_404”

```
events {}

http {

  include mime.types;

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

    try_files $uri /cat.png /greet @friendly_404;

    location @friendly_404 {
      return 404 "Sorry, that file could not be found.";
    }

    location /greet {
      return 200 "Hello User";
    }

  }
}
```

error log path:

- the error log path for NGINX can be found in the NGINX configuration file. [By default, on most Linux distributions such as Ubuntu, CentOS, and Debian, the error log is located at **`/var/log/nginx/error.log`**1](https://www.digitalocean.com/community/tutorials/nginx-access-logs-error-logs)[2](https://linuxize.com/post/nginx-log-files/).
- However, the location can be customized in the NGINX configuration file. [The **`error_log`** directive in the configuration file sets up logging to a particular file](https://www.digitalocean.com/community/tutorials/nginx-access-logs-error-logs)[3](https://docs.nginx.com/nginx/admin-guide/monitoring/logging/). Here is an example of how it might look:
    
    `error_log /path/to/your/error.log;`
    

Example

```groovy
events {}

http {

  include mime.types;

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

    location /secure {

      # Add context specific log
      access_log /var/log/nginx/secure.access.log;

      # Disable logs for context
      #access_log off;

      return 200 "Welcome to secure area.";
    }

  }
}
```

Nginx isn’t enabled to embed its server side language processors, so instead we configure PHP service named PHP / FPM and it receive the response on HTML and send it back to the client “act as reverse proxy”

```groovy
sudo apt update
sudo apt-get install php-fpm
# check if is installed
systemctl list-units | grep php
```

We run the nginx.config as www-data user for “fpm permission”

```groovy
ps aux | grep php
```

### check video php proccessing

```groovy
# run the script as www-data user 
user www-data;

events {}

http {

  include mime.types;

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

		# check index.php -> if not existed check index.html in root directive
    index index.php index.html;

    location / {
			# check all them -> if not existed 404
      try_files $uri $uri/ =404;
    }

			
    location ~\.php$ {
			# location ~ will take the highest priority 
			# check using regular expression any file with ending .php
      # Pass php requests to the php-fpm service (fastcgi)
			# fastcgi is just a network protocol like HTTP for passing binary data
			# fastcgi for communication between php and fpm
			# you will need to type the following command to find the path of fpm socket "used in fastcgi_pass parameter"
					# find / -name *fpm.sock

      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock;
    }

  }
}
```

## Nginx Performance:

worker_processes : how many process in the cpu can be handled for nginx 

Note:  adding more worker_processes doesn’t mean high performance it depends on the physical hardware → how many CPU core are there ?

Example: if you have VM with 1 core with work_processess= 2 means these two processess can be 50% each inside the single core

Summary: ***worker_processes directive in the main Nginx configuration context should match the number of CPU Cores***

### max connections = worker_connections * worker_processes

```groovy
# how many cores are in the VM
nproc

# describe cpu information
lscpu

# worker_connections -> how many files can be opened at once for each CPU Core
ulimit -n

# max connections = worker_connections * worker_processes 
```

```groovy
user www-data;

worker_processes auto;

events {
  worker_connections 1024;
}

http {

  include mime.types;

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

    index index.php index.html;

    location / {
      try_files $uri $uri/ =404;
    }

    location ~\.php$ {
      # Pass php requests to the php-fpm service (fastcgi)
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock;
    }

  }
}
```

### Buffers & Timeouts:

[](https://pwcanalytics.udemy.com/course/nginx-fundamentals/learn/lecture/10615124#questions)

**buffering**: when process/worker reads data into memory/ram before writing to next destination

```groovy
user www-data;

worker_processes auto;

events {
  worker_connections 1024;
}

http {

  include mime.types;

  # Buffer size for POST submissions
  client_body_buffer_size 10K;
  client_max_body_size 8m;

  # Buffer size for Headers
  client_header_buffer_size 1k;

  # Max time to receive client headers/body
  client_body_timeout 12;
  client_header_timeout 12;

  # Max time to keep a connection open for
  keepalive_timeout 15;

  # Max time for the client accept/receive a response
  send_timeout 10;

  # Skip buffering for static files
  sendfile on;

  # Optimise sendfile packets
  tcp_nopush on;

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

    index index.php index.html;

    location / {
      try_files $uri $uri/ =404;
    }

    location ~\.php$ {
      # Pass php requests to the php-fpm service (fastcgi)
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock;
    }

  }
}
```

### Adding dynamic modules

[](https://pwcanalytics.udemy.com/course/nginx-fundamentals/learn/lecture/10615142#questions)

### Headers & Expires

- expires header: response header on client on how long it can cache that response for
    - add_header
    - expires
- to check any respose

```groovy
curl -I request
```

```groovy
user www-data;

worker_processes auto;

events {
  worker_connections 1024;
}

http {

  include mime.types;

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

    index index.php index.html;

    location / {
      try_files $uri $uri/ =404;
    }

    location ~\.php$ {
      # Pass php requests to the php-fpm service (fastcgi)
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock;
    }

   
    # anything with css|js|jpg|png will be cached 
    location ~* \.(css|js|jpg|png)$ {
      access_log off;
      add_header Cache-Control public;
      add_header Pragma public;
      add_header Vary Accept-Encoding;
      expires 1M;
    }

  }
}
```

### compressed response “gzip”

- compress a response on the server with gzip to reduce the size and the client/browser has the responsiblity to decompress before rendering: PARAMETERS USED ARE → “gzip“ “gzip_comp_level“ “gzip_types“
    - gzip_comp_level between 3 or 4 is recommended
    - need to add_header Vary Accept-Encoding; is must

example:

```groovy
user www-data;

worker_processes auto;

events {
  worker_connections 1024;
}

http {

  include mime.types;
	
	# add gzip required parameters
  gzip on;
  gzip_comp_level 3;

  gzip_types text/css;
  gzip_types text/javascript;

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

    index index.php index.html;

    location / {
      try_files $uri $uri/ =404;
    }

    location ~\.php$ {
      # Pass php requests to the php-fpm service (fastcgi)
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock;
    }

    location ~* \.(css|js|jpg|png)$ {
      access_log off;
      add_header Cache-Control public;
      add_header Pragma public;

			# must be added so client must accept coding before receiving gzip responses
      add_header Vary Accept-Encoding;
      expires 1M;
    }

  }
}
```

### FastCGI Cache:

[](https://pwcanalytics.udemy.com/course/nginx-fundamentals/learn/lecture/10615290#learning-tools)

- Nginx micro → simple server side cache that allow to store dynamic responses
- to test it → use Apache Bench

```groovy

apt update
apt-get install apache2-utils
ab
# Test it with 10 requests with 10 concurrent connections level
ab -n <REQUEST_NUMBERS> -c <CONNECTION_NUMBERS> IP_REQUEST
```

- Example:

```groovy
user www-data;

worker_processes auto;

events {
  worker_connections 1024;
}

http {

  include mime.types;

  # Configure microcache (fastcgi)
  fastcgi_cache_path /tmp/nginx_cache levels=1:2 keys_zone=ZONE_1:100m inactive=60m;
  fastcgi_cache_key "$scheme$request_method$host$request_uri";
  add_header X-Cache $upstream_cache_status;

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

    index index.php index.html;

    # Cache by default
    set $no_cache 0;

    # Check for cache bypass
    if ($arg_skipcache = 1) {
      set $no_cache 1;
    }

    location / {
      try_files $uri $uri/ =404;
    }

    location ~\.php$ {
      # Pass php requests to the php-fpm service (fastcgi)
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock;

      # Enable cache
      fastcgi_cache ZONE_1;
      fastcgi_cache_valid 200 60m;
      fastcgi_cache_bypass $no_cache;
      fastcgi_no_cache $no_cache;
    }

  }
}
```

### HTTP 2

- Binary Protocol unlike http1 text protocol
- Compressed headers
- Persistent Connections
- Multiplex Streaming → (CSS,JS) can be compained over a single binary data and transmitted over single connection
- Server push → client/browser can be informed with assets along with intial request
- A requirement of Http2 is *SSL or Https*
- Steps:
    - Add http2 module to nginx configurations
    - - -with-http-v2-module
    
    ![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/62507ca7-49b9-466f-a316-922da6c8e3b4/7075d73c-eda3-4ecb-af0b-a3aaa03934a4/Untitled.png)
    
    ```bash
    # in order to enable https, you must create ssl certificate
    mkdir /etc/nginx/ssl
    # create ssl certificate with expiration of 10 days set the key and certificate into 
    # /etc/nginx/ssl/ with names self.key and self.crt
    openssl req -x509 -days 10 -nodes -newkey rsa:2048 -keyout /etc/nginx/ssl/self.key -out /etc/nginx/ssl/self.crt
    ```
    

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/62507ca7-49b9-466f-a316-922da6c8e3b4/8b36cea4-005e-4651-a65f-964ea688170b/Untitled.png)

nginx.config

```bash
user www-data;

worker_processes auto;

events {
  worker_connections 1024;
}

http {

  include mime.types;

  server {

		# add port 443 for https and ssl with http2 protocol
    # for VM please open inbound rule for 443
    listen 443 ssl http2;
    server_name 172.210.49.88;

    root /sites/demo;

    index index.php index.html;

		# set the path of ssl key and certificate
    # it will not conside as a secure option as it is ssl self signed cert
    ssl_certificate /etc/nginx/ssl/self.crt;
    ssl_certificate_key /etc/nginx/ssl/self.key;

    location / {
      try_files $uri $uri/ =404;
    }

    location ~\.php$ {
      # Pass php requests to the php-fpm service (fastcgi)
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.4-fpm.sock;
    }

  }
}
```

**Note:** 

- *In case of self-signed SSL, it will not be considered secure but we do it for demo purposes*
    - if you try to use it in chrome it will automatically redirect to http 1 because ssl is self-signed
    - the only option to test self-sign using curl -I -K

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/62507ca7-49b9-466f-a316-922da6c8e3b4/eedeca8f-e622-48fb-ad78-b8881d31ccfa/Untitled.png)

### Http2: Server Push

[Introducing HTTP/2 Server Push with NGINX 1.13.9 | NGINX](https://www.nginx.com/blog/nginx-1-13-9-http2-server-push/)

- Basically server push is a feature with http2 that lets client/browser can be informed with assets along with intial request
- in this example we will link css and png of the web site with the intial request of html
- to test this we will need to setup nghttp2 client

```bash
apt-get install nghttp2-client -y
# to test all requests
# -n: discard responses and not storing in the disk
# -y: ignore self-signed cert
# -s: print statistics
# -a: link all the assets linked to this request

# with all assets
nghttp -nysa <https://"IP_OR_DOMAIN"/>

# without assets
nghttp -nys <https://"IP_OR_DOMAIN"/path>
```

- nginx.conifg

```bash
user www-data;

worker_processes auto;

events {
  worker_connections 1024;
}

http {

  include mime.types;

  server {

    listen 443 ssl http2;
    server_name 167.99.93.26;

    root /sites/demo;

    index index.php index.html;

    ssl_certificate /etc/nginx/ssl/self.crt;
    ssl_certificate_key /etc/nginx/ssl/self.key;

		# when the client calls index.html -> service push css and png file with it
    location = /index.html {
      http2_push /style.css;
      http2_push /thumb.png;
    }

    location / {
      try_files $uri $uri/ =404;
    }

    location ~\.php$ {
      # Pass php requests to the php-fpm service (fastcgi)
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock;
    }

  }
}
```

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/62507ca7-49b9-466f-a316-922da6c8e3b4/15811e9d-11a3-43bd-878e-d16ee5acc485/Untitled.png)

## Security Section

### Https:

Note: SSL is outdated, we recommend to use TLS only

we do this by doing the following:

- Disable SSL and only enable TLS
- Optimise ssl cipher suits
- create DH pem and enableing it nginx.config
    - allows server to exchange between client and server with perfect secrecy
        
        ```bash
        openssl dhparam 2048 -out <WHERE_YOU_SHOULD_SAVE_IT>
        
        ```
        
- enable HSTS → header tells the browser not to load anything over Http
- Cache SSL Sessions
    - enable session cache → shared
    - enable session tickets → provide a ticket to validate ssl session issued by the server

nginx.config

```bash
user www-data;

worker_processes auto;

events {
  worker_connections 1024;
}

http {

  include mime.types;

  # Redirect all traffic to HTTPS
  server {
    listen 80;
    server_name 167.99.93.26;
    return 301 https://$host$request_uri;
  }

  server {

    listen 443 ssl http2;
    server_name 167.99.93.26;

    root /sites/demo;

    index index.html;

    ssl_certificate /etc/nginx/ssl/self.crt;
    ssl_certificate_key /etc/nginx/ssl/self.key;

    # Disable SSL
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

    # Optimise cipher suits
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDH+AESGCM:ECDH+AES256:ECDH+AES128:DH+3DES:!ADH:!AECDH:!MD5;

    # Enable DH Params
    ssl_dhparam /etc/nginx/ssl/dhparam.pem;

    # Enable HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;

    # SSL sessions
    ssl_session_cache shared:SSL:40m;
    ssl_session_timeout 4h;
    ssl_session_tickets on;

    location / {
      try_files $uri $uri/ =404;
    }

    location ~\.php$ {
      # Pass php requests to the php-fpm service (fastcgi)
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock;
    }

  }
}
```

### Rate Limiting:

[](https://pwcanalytics.udemy.com/course/nginx-fundamentals/learn/lecture/10617504#questions)

- Managing incoming connections to the server for reason as:
    - Brutle Force Protectiong
    - Prevent traffic spikes
    - Service Priority
- To test server rate limiting using tool called “Siege” load testing tool

```bash
apt-get install siege

# verbose logging run 2 test on 5 concurrent connections
siege -v -r 2 -c 5 <request>
```

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/62507ca7-49b9-466f-a316-922da6c8e3b4/def9c81d-29a4-4366-a503-1681cdee7247/Untitled.png)

- Steps:
    - define limit zone
    - set limit to a location
    
    ```bash
    user www-data;
    
    worker_processes auto;
    
    events {
      worker_connections 1024;
    }
    
    http {
    
      include mime.types;
    
      # Define limit zone
      limit_req_zone $request_uri zone=MYZONE:10m rate=1r/s;
    
      # Redirect all traffic to HTTPS
      server {
        listen 80;
        server_name 167.99.93.26;
        return 301 https://$host$request_uri;
      }
    
      server {
    
        listen 443 ssl http2;
        server_name 167.99.93.26;
    
        root /sites/demo;
    
        index index.html;
    
        ssl_certificate /etc/nginx/ssl/self.crt;
        ssl_certificate_key /etc/nginx/ssl/self.key;
    
        # Disable SSL
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    
        # Optimise cipher suits
        ssl_prefer_server_ciphers on;
        ssl_ciphers ECDH+AESGCM:ECDH+AES256:ECDH+AES128:DH+3DES:!ADH:!AECDH:!MD5;
    
        # Enable DH Params
        ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    
        # Enable HSTS
        add_header Strict-Transport-Security "max-age=31536000" always;
    
        # SSL sessions
        ssl_session_cache shared:SSL:40m;
        ssl_session_timeout 4h;
        ssl_session_tickets on;
    
        location / {
          limit_req zone=MYZONE burst=5 nodelay;
          try_files $uri $uri/ =404;
        }
    
        location ~\.php$ {
          # Pass php requests to the php-fpm service (fastcgi)
          include fastcgi.conf;
          fastcgi_pass unix:/run/php/php7.1-fpm.sock;
        }
    
      }
    }
    ```
    

### Basic Auth

- Providing simple username and password layer
    - generate password in .htpasswd
    - add  auth_basic and auth_basic_user*_*file
    
    ```bash
    apt-get install apache2-utils
    
    # create password for user "rizk"
    htpasswd -c /etc/nginx/.htpasswd rizk
    
    ```
    
    nginx.config
    
    ```bash
    user www-data;
    
    worker_processes auto;
    
    events {
      worker_connections 1024;
    }
    
    http {
    
      include mime.types;
    
      # Define limit zone
      limit_req_zone $request_uri zone=MYZONE:10m rate=1r/s;
    
      # Redirect all traffic to HTTPS
      server {
        listen 80;
        server_name 167.99.93.26;
        return 301 https://$host$request_uri;
      }
    
      server {
    
        listen 443 ssl http2;
        server_name 167.99.93.26;
    
        root /sites/demo;
    
        index index.html;
    
        ssl_certificate /etc/nginx/ssl/self.crt;
        ssl_certificate_key /etc/nginx/ssl/self.key;
    
        # Disable SSL
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    
        # Optimise cipher suits
        ssl_prefer_server_ciphers on;
        ssl_ciphers ECDH+AESGCM:ECDH+AES256:ECDH+AES128:DH+3DES:!ADH:!AECDH:!MD5;
    
        # Enable DH Params
        ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    
        # Enable HSTS
        add_header Strict-Transport-Security "max-age=31536000" always;
    
        # SSL sessions
        ssl_session_cache shared:SSL:40m;
        ssl_session_timeout 4h;
        ssl_session_tickets on;
    
        location / {
    			# FOR AUTH ADD TEXT AND PATH OF htpasswd
          auth_basic "Secure Area";
          auth_basic_user_file /etc/nginx/.htpasswd;
    
          try_files $uri $uri/ =404;
        }
    
      }
    }
    ```
    
    ![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/62507ca7-49b9-466f-a316-922da6c8e3b4/af70d084-8a2c-4078-a486-9ac3d023f554/Untitled.png)
    

### Nginx Harden:

- set server_token off → To make client not knowing your nginx version
- securing our NGINX install by **removing unused default module**

## Reverse Proxy and Load Balancer:

- Reverse Proxy:
    
    [NGINX Reverse Proxy](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/)
    
    [Module ngx_http_proxy_module](http://nginx.org/en/docs/http/ngx_http_proxy_module.html)
    
    nginx.config
    
    ```bash
    events {}
    
    http {
    
      server {
    
        listen 8888;
    
        location /  {
          return 200 "Hello User\n";
        }
    
        location /php {
    
         # add proxy header
         proxy_set_header pro zoka;
         # add header
         add_header proxied rizk;
         # reverse proxy to localhost:8000
         proxy_pass 'http://localhost:8000/';
        }
    
      }
    }
    ```
    
- Loadbalancer:
    
    [HTTP Load Balancing](https://docs.nginx.com/nginx/admin-guide/load-balancer/http-load-balancer/)
    
    [Using nginx as HTTP load balancer](http://nginx.org/en/docs/http/load_balancing.html)
    
    - Steps:
        - add upstream with server collection
        - proxy_pass to the upstream
        
        ```bash
        events {}
        
        http {
            # we have created three servers on the local host with the following ports 
            # php -S localhost:10001 s1
            # php -S localhost:10002 s2
            # php -S localhost:10003 s3
        
            # For the load balancer
        		# Step1
            # add server collection 
            upstream phps {
              server localhost:10001;
              server localhost:10002;
              server localhost:10003;
            }
        
          server {
            listen 8888;
            location / {
        			# Step2
              # reverse proxy to collection of servers "loadbalancer"
              proxy_pass http://phps;
            }
          }
        }
        ```
        
        ## References that may help:
        
        https://github.com/fcambus/nginx-resources
        
        [nginx documentation](http://nginx.org/en/docs/)
        
        [Pitfalls and Common Mistakes | NGINX](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/)
        
        [Nginx – Advanced Administration Handbook | Developer.WordPress.org](https://developer.wordpress.org/advanced-administration/server/web-server/nginx/)
