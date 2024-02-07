# Nginx

Created: February 4, 2024 1:10 PM
Class: AWS
Type: Lecture
Reviewed: No
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

- Nginx micro → simple server side cache that allow to store dynamic responses
