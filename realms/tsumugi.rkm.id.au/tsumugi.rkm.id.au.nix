# logical specification

let

  sshKeys = import ./../../common/ssh-keys.nix;
  secrets = import ./secrets.nix;

in

{
  network.description = "tsumugi.rkm.id.au";

  tsumugi = { config, lib, pkgs, ... }:
  {
    # imports = [ ../../local/modules/module-list.nix ];

    boot = {
      loader = {
        efi.efiSysMountPoint = "/boot/efi";
        grub = {
          enable = true;
          version = 2;
          efiSupport = true;
          device = "/dev/vda"; # or "nodev" for efi only
        };
      };
      initrd.luks.devices = [{
        name = "root";
        device = "/dev/vda3";
        allowDiscards = true;
      }];
    };

    networking = {
      hostName = "tsumugi";
      firewall = {
        enable = true;
        allowedTCPPorts = [
          22
          80
          443
          3478 # coturn
          8448 # matrix
        ];
        allowedUDPPorts = [
          3478 # coturn
        ];
        allowedUDPPortRanges = [
          { from = 49152; to = 65535; } # coturn
        ];
      };
    };

    i18n = {
      consoleFont = "Lat2-Terminus16";
      consoleKeyMap = "us";
      defaultLocale = "en_US.UTF-8";
    };

    time.timeZone = "Adelaide/Australia";

    environment = {
      systemPackages = with pkgs; [
        nextcloud
        bash
        bind
        bzip2
        coreutils
        curlFull
        direnv
        emacs
        file
        findutils
        gcc
        git
        gitAndTools.git-crypt
        gitAndTools.gitFull
        gnugrep
        gnumake
        gnupg21
        inetutils
        nix-zsh-completions
        nmap
        openssl
        pwgen
        rsync
        stow
        telnet
        tmux
        tree
        unzip
        wget
        which
        whois
        zsh
        zsh-completions
      ];
      pathsToLink = [ "/include" ];
    };

    services.matrix-synapse = {
      allow_guest_access = false;
      bcrypt_rounds = "12";
      enable = true;
      web_client = false;
      enable_registration = false;
      registration_shared_secret = secrets.services.matrix-synapse.registration_shared_secret;
      server_name = "matrix.rkm.id.au";
      database_type = "psycopg2";
      database_args = {
        user = "synapse";
        password = secrets.services.matrix-synapse.database_args.password;
        database = "matrix-synapse";
        host = "localhost";
        cp_min = "5";
        cp_max = "10";
      };
      turn_uris = [
       "turn:turn.rkm.id.au:3478?transport=udp"
        "turn:turn.rkm.id.au:3478?transport=tcp"
      ];
      # This needs to be the same as services.coturn.static-auth-secret
      turn_shared_secret = secrets.services.matrix-synapse.turn_shared_secret;
      turn_user_lifetime = "24h";
      url_preview_enabled = true;
    };

    services.nginx = {
      enable = true;
      user = "www-data";
      group = "www-data";
      virtualHosts =
      let
        commonVirtualHostConfig = {
          enableSSL = true;
          forceSSL = true;
          locations = {
            "/.well-known/acme-challenge" = {
              root = "/var/www/challenges";
            };
            "= /robots.txt" = {
              extraConfig = ''
                allow all;
                log_not_found off;
                access_log off;
              '';
            };
          };
        };
      in {
        "nextcloud.rkm.id.au" = commonVirtualHostConfig // {
          root = pkgs.nextcloud;
          locations = commonVirtualHostConfig.locations // {
            "~ ^/(?:\.htaccess|data|config|db_structure\.xml|README)" = {
              extraConfig = "deny all;";
            };
            "/" = {
              extraConfig = ''
                # The following 2 rules are only needed with webfinger
                rewrite ^/.well-known/host-meta /public.php?service=host-meta last;
                rewrite ^/.well-known/host-meta.json /public.php?service=host-meta-json last;
                rewrite ^/.well-known/carddav /remote.php/carddav/ redirect;
                rewrite ^/.well-known/caldav /remote.php/caldav/ redirect;
                rewrite ^(/core/doc/[^\/]+/)$ $1/index.html;
                try_files $uri $uri/ /index.php;
              '';
            };
            "~ \.php(?:$|/)" = {
              extraConfig = ''
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                include ${pkgs.nginx}/conf/fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_param PATH_INFO $fastcgi_path_info;
                fastcgi_param HTTPS on;
                fastcgi_pass unix:/run/phpfpm/nginx;
                fastcgi_intercept_errors on;
              '';
            };
            "~* \.(?:css|js)$" = {
              extraConfig = ''
                # Add cache control header for js and css files.
                # Make sure it is below the "~ \.php(?:$|/)" block.
                add_header Cache-Control "public, max-age=7200";
                # Add headers to serve security related headers
                add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;";
                add_header X-Content-Type-Options nosniff;
                add_header X-Frame-Options "SAMEORIGIN";
                add_header X-XSS-Protection "1; mode=block";
                add_header X-Robots-Tag none;
                # Optional: Don't log access to assets.
                access_log off;
              '';
            };
            "~* \.(?:jpg|jpeg|gif|bmp|ico|png|swf)$" = {
              extraConfig = ''
                # Optional: Don't log access to other assets.
                access_log off;
              '';
            };
          };
          extraConfig = ''
            client_max_body_size 10G;
            fastcgi_buffers 64 4K;
            gzip off; # Disable gzip to avoid the removal of the ETag header.
            rewrite ^/caldav(.*)$ /remote.php/caldav$1 redirect;
            rewrite ^/carddav(.*)$ /remote.php/carddav$1 redirect;
            rewrite ^/webdav(.*)$ /remote.php/webdav$1 redirect;
            index index.php;
            error_page 403 /core/templates/403.php;
            error_page 404 /core/templates/404.php;
          '';
          sslCertificate = "/var/lib/acme/nextcloud.rkm.id.au/fullchain.pem";
          sslCertificateKey = "/var/lib/acme/nextcloud.rkm.id.au/key.pem";
        };
        "matrix.rkm.id.au" = commonVirtualHostConfig // {
          locations = {
            "/.well-known/acme-challenge" = {
              root = "/var/www/challenges";
            };
            "/" = {
              proxyPass = "https://127.0.0.1:8448";
            };
          };
          sslCertificate = "/var/lib/acme/matrix.rkm.id.au/fullchain.pem";
          sslCertificateKey = "/var/lib/acme/matrix.rkm.id.au/key.pem";
        };
        "_" = {
          default = true;
          locations = commonVirtualHostConfig.locations;
        };
      };
    };

    systemd.services.nextcloud-startup = {
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = pkgs.writeScript "nextcloud-startup" ''
          #! ${pkgs.bash}/bin/bash
          NEXTCLOUD_PATH="/var/lib/nextcloud"

          if (! test -e "''${NEXTCLOUD_PATH}" \
                -o -e "''${NEXTCLOUD_PATH}/apps" \
                -o -e "''${NEXTCLOUD_PATH}/config" \
                -o -e "''${NEXTCLOUD_PATH}/data"); then
            mkdir -p "''${NEXTCLOUD_PATH}/"{,apps,config,data}
            chmod 700 /var/lib/nextcloud
            chown -R www-data:www-data /var/lib/nextcloud
          fi
      '';
      };
      enable = true;
    };

    services.phpfpm.poolConfigs.nginx = ''
      user = www-data
      group = www-data
      listen = /run/phpfpm/nginx
      listen.owner = www-data
      listen.group = www-data
      pm = dynamic
      pm.max_children = 5
      pm.start_servers = 2
      pm.min_spare_servers = 1
      pm.max_spare_servers = 3
      pm.max_requests = 500

      env[NEXTCLOUD_CONFIG_DIR] = /var/lib/nextcloud/config
      php_flag[display_errors] = off
      php_admin_value[error_log] = /run/phpfpm/php-fpm.log
      php_admin_flag[log_errors] = on
      php_value[date.timezone] = "UTC"
      php_value[upload_max_filesize] = 10G
    '';

    services.coturn = {
      enable = true;
      lt-cred-mech = true;
      static-auth-secret = secrets.services.coturn.static-auth-secret;
      realm = "turn.rkm.id.au";
      cert = "/var/lib/acme/matrix.rkm.id.au/fullchain.pem";
      pkey = "/var/lib/acme/matrix.rkm.id.au/key.pem";
      min-port = 49152;
      max-port = 65535;
    };

    security.acme.certs =
    let
      commonAcmeConfig = {
        webroot = "/var/www/challenges";
        email = "r@rkm.id.au";
        plugins = [
          "account_key.json"
          "cert.pem"
          "chain.pem"
          "fullchain.pem"
          "key.pem"
        ];
      };
    in {
      "nextcloud.rkm.id.au" = commonAcmeConfig // {
        postRun = "systemctl reload-or-restart nginx";
      };
      "matrix.rkm.id.au" = commonAcmeConfig // {
        extraDomains = {
          "turn.rkm.id.au" = null;
        };
        postRun = "systemctl reload-or-restart nginx matrix-synapse";
      };
    };

    services.postgresql.enable = true;
    services.openssh.enable = true;
    services.fail2ban.enable = true;

    programs.zsh.enable = true;

    users.extraUsers = {
      root = {
        openssh.authorizedKeys.keys = [
         sshKeys.rkm
       ];
      };
      eqyiel = {
        isNormalUser = true;
        initialPassword = "hunter2";
        extraGroups = [ "wheel" "systemd-journal" ];
        shell = pkgs.zsh;
        openssh.authorizedKeys.keys = [
          sshKeys.rkm
        ];
      };
      www-data = {
        isNormalUser = false;
        group = "www-data";
        home = "/var/www";
        createHome = true;
      };
    };

    users.groups.www-data.name = "www-data";

    nix.gc.automatic = true;
  };
}
