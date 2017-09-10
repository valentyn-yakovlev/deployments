{ config, lib, pkgs, ... }:
let

nextcloudPath = "/var/lib/nextcloud";
hostname = "cloud.rkm.id.au";
commonAcmeConfig = (import ./common-acme-config.nix).commonAcmeConfig;

in {
  services.nginx.virtualHosts."${hostname}" = {
    onlySSL = true;
    enableACME = true;
    # sslCertificate = "/var/lib/acme/${hostname}/fullchain.pem";
    # sslCertificateKey = "/var/lib/acme/${hostname}/key.pem";
    extraConfig = ''
      # Add headers to serve security related headers
      # Before enabling Strict-Transport-Security headers please read into this
      # topic first.
      # add_header Strict-Transport-Security "max-age=15768000;
      # includeSubDomains; preload;";
      #
      # WARNING: Only add the preload option once you read about
      # the consequences in https://hstspreload.org/. This option
      # will add the domain to a hardcoded list that is shipped
      # in all major browsers and getting removed from this list
      # could take several months.
      add_header X-Content-Type-Options nosniff;
      add_header X-XSS-Protection "1; mode=block";
      add_header X-Robots-Tag none;
      add_header X-Download-Options noopen;
      add_header X-Permitted-Cross-Domain-Policies none;

      # Path to the root of your installation
      root ${pkgs.nextcloud};

      location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
      }

      # The following 2 rules are only needed for the user_webfinger app.
      # Uncomment it if you're planning to use this app.
      #rewrite ^/.well-known/host-meta /public.php?service=host-meta last;
      #rewrite ^/.well-known/host-meta.json /public.php?service=host-meta-json
      # last;

      location = /.well-known/carddav {
        return 301 $scheme://$host/remote.php/dav;
      }

      location = /.well-known/caldav {
        return 301 $scheme://$host/remote.php/dav;
      }

      # set max upload size
      client_max_body_size 10G;
      fastcgi_buffers 64 4K;

      # Enable gzip but do not remove ETag headers
      gzip on;
      gzip_vary on;
      gzip_comp_level 4;
      gzip_min_length 256;
      gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
      gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

      # Uncomment if your server is build with the ngx_pagespeed module
      # This module is currently not supported.
      #pagespeed off;

      location / {
        rewrite ^ /index.php$uri;
      }

      location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)/ {
        deny all;
      }

      location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console) {
        deny all;
      }

      location ~ ^/(?:index|remote|public|cron|core/ajax/update|status|ocs/v[12]|updater/.+|ocs-provider/.+)\.php(?:$|/) {
        fastcgi_split_path_info ^(.+\.php)(/.*)$;
        include ${pkgs.nginx}/conf/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_param HTTPS on;
        #Avoid sending the security headers twice
        fastcgi_param modHeadersAvailable true;
        fastcgi_param front_controller_active true;
        fastcgi_pass unix:/run/phpfpm/nextcloud;
        fastcgi_intercept_errors on;
        fastcgi_request_buffering off;
      }

      location ~ ^/(?:updater|ocs-provider)(?:$|/) {
        try_files $uri/ =404;
        index index.php;
      }

      # Adding the cache control header for js and css files
      # Make sure it is BELOW the PHP block
      location ~ \.(?:css|js|woff|svg|gif)$ {
        try_files $uri /index.php$uri$is_args$args;
        add_header Cache-Control "public, max-age=15778463";
        # Add headers to serve security related headers (It is intended to
        # have those duplicated to the ones above)
        # Before enabling Strict-Transport-Security headers please read into
        # this topic first.
        # add_header Strict-Transport-Security "max-age=15768000;
        #  includeSubDomains; preload;";
        #
        # WARNING: Only add the preload option once you read about
        # the consequences in https://hstspreload.org/. This option
        # will add the domain to a hardcoded list that is shipped
        # in all major browsers and getting removed from this list
        # could take several months.
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header X-Robots-Tag none;
        add_header X-Download-Options noopen;
        add_header X-Permitted-Cross-Domain-Policies none;
        # Optional: Don't log access to assets
        access_log off;
      }

      location ~ \.(?:png|html|ttf|ico|jpg|jpeg)$ {
        try_files $uri /index.php$uri$is_args$args;
        # Optional: Don't log access to other assets
        access_log off;
      }

      location ^~ /apps_addon {
        alias ${nextcloudPath}/apps;
      }

      location ^~ /apps_internal {
        alias ${pkgs.nextcloud}/apps;
      }
    '';
  };

  services.postgresql.enable = true;

  systemd.services.nextcloud-startup = {
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = pkgs.writeScript "nextcloud-startup" ''
        #! ${pkgs.bash}/bin/bash
        NEXTCLOUD_PATH="${nextcloudPath}"
        if (! test -e "''${NEXTCLOUD_PATH}"); then
          mkdir -p "''${NEXTCLOUD_PATH}/"{,config,data}
          cp -r "${pkgs.nextcloud}/apps" "''${NEXTCLOUD_PATH}"
          chmod 755 "''${NEXTCLOUD_PATH}"
          chown -R www-data:www-data "''${NEXTCLOUD_PATH}"
        fi

        if (test -L "''${NEXTCLOUD_PATH}/apps_internal"); then
          rm "''${NEXTCLOUD_PATH}/apps_internal"
        fi

        if (! test -e "''${NEXTCLOUD_PATH}/apps_internal"); then
          ln -s ${pkgs.nextcloud}/apps "''${NEXTCLOUD_PATH}/apps_internal"
        fi
    '';
    };
    enable = true;
  };

  systemd.services.nextcloud-cron = {
    after = [ "network.target" ];
    script = ''
      ${pkgs.php}/bin/php ${pkgs.nextcloud}/cron.php
      ${pkgs.nextcloud-news-updater}/bin/nextcloud-news-updater -i 15 --mode singlerun ${pkgs.nextcloud}
    '';
    environment = { NEXTCLOUD_CONFIG_DIR = "${nextcloudPath}/config"; };
    serviceConfig.User = "www-data";
  };

  systemd.timers.nextcloud-cron = {
    enable = true;
    wantedBy = [ "timers.target" ];
    partOf = [ "nextcloud-cron.service" ];
    timerConfig = {
      OnCalendar = "*-*-* *:00,15,30,45:00";
      Persistent = true;
    };
  };

  services.phpfpm.poolConfigs.nextcloud = ''
    user = www-data
    group = www-data
    listen = /run/phpfpm/nextcloud
    listen.owner = www-data
    listen.group = www-data
    pm = dynamic
    pm.max_children = 5
    pm.start_servers = 2
    pm.min_spare_servers = 1
    pm.max_spare_servers = 3
    pm.max_requests = 500
    env[NEXTCLOUD_CONFIG_DIR] = "${nextcloudPath}/config"
    php_flag[display_errors] = off
    php_admin_value[error_log] = /run/phpfpm/php-fpm.log
    php_admin_flag[log_errors] = on
    php_value[date.timezone] = "UTC"
    php_value[upload_max_filesize] = 10G
    php_value[cgi.fix_pathinfo] = 1
  '';
}
