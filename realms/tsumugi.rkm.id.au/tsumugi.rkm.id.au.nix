# logical specification

let

  sshKeys = import ./../../local/common/ssh-keys.nix;
  secrets = import ./secrets.nix;
  commonAcmeConfig = (import ./common-acme-config.nix).commonAcmeConfig;

in

{
  network.description = "tsumugi.rkm.id.au";

  tsumugi = { config, lib, pkgs, ... }:
  {
    imports = [
     # ../../local/modules/module-list.nix
     ./dhparams.nix
     ./nextcloud.nix
     ./rsvp.fyi.nix
     ./syncthing.nix
     ./mail-server.nix
    ];

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
      hostName = "tsumugi.rkm.id.au";
      firewall = {
        enable = true;
        allowedTCPPorts = [
          22 # ssh, sftp
          25 # smtp
          80 # http
          443 # https
          587 # smtps
          3478 # coturn
          8448 # matrix
          993 # imaps
        ];
        allowedUDPPorts = [
          3478 # coturn
        ];
        allowedUDPPortRanges = [
          { from = 49152; to = 65535; } # coturn
        ];
        trustedInterfaces = [ "lo" ];
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
        gnupg22
        inetutils
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
      # sslProtocols = "TLSv1 TLSv1.1 TLSv1.2";
      appendConfig = ''
        error_log stderr info;
      '';
      virtualHosts = {
        "rkm.id.au" =  {
          onlySSL = true;
          enableACME = true;
          root = "/var/www/public_html/rkm.id.au";
        };

        "matrix.rkm.id.au" = {
          onlySSL = true;
          locations = {
            "/" = {
              proxyPass = "https://127.0.0.1:8448";
            };
            "/.well-known/acme-challenge" = {
              root = "/var/lib/acme/acme-challenge";
            };
            "= /robots.txt" = {
              extraConfig = ''
                allow all;
                log_not_found off;
                access_log off;
              '';
            };
          };

          sslCertificate = "/var/lib/acme/matrix.rkm.id.au/fullchain.pem";
          sslCertificateKey = "/var/lib/acme/matrix.rkm.id.au/key.pem";
        };

        "_" = {
          default = true;
          locations = {
            "/.well-known/acme-challenge" = {
              root = "/var/lib/acme/acme-challenge";
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
      };
    };

    systemd.services.nginx-startup = {
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      unitConfig = {
        Before = "nginx.service";
      };
      serviceConfig = {
        ExecStart = pkgs.writeScript "nginx-startup" ''
          #! ${pkgs.bash}/bin/bash
          if (! test -e "/var/www/public_html"); then
            mkdir -p "/var/www/public_html"
            chmod 770 "/var/www/public_html"
            chown -R www-data:www-data "/var/www/public_html"
          fi
        '';
      };
      enable = true;
    };

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

    security.acme.certs = {
      "rkm.id.au" = commonAcmeConfig // {
        postRun = "systemctl reload-or-restart nginx";
      };
      "matrix.rkm.id.au" = commonAcmeConfig // {
        webroot = "/var/lib/acme/acme-challenge";
        extraDomains = {
          "turn.rkm.id.au" = null;
        };
        postRun = "systemctl reload-or-restart matrix-synapse coturn";
      };
    };

    services.postgresql.enable = true;

    services.openssh.enable = true;
    services.openssh.permitRootLogin = "yes";

    services.fail2ban.enable = true;

    programs.zsh.enable = true;

    users.mutableUsers = false;

    users.users = {
      root = {
        openssh.authorizedKeys.keys = [
         sshKeys.rkm
       ];
       inherit (secrets.users.users.root) initialPassword;
     };
      eqyiel = {
        isNormalUser = true;
        extraGroups = [ "wheel" "systemd-journal" "www-data" ];
        shell = pkgs.zsh;
        openssh.authorizedKeys.keys = [
          sshKeys.rkm
        ];
        inherit (secrets.users.users.eqyiel) initialPassword;
      };
      www-data = {
        isNormalUser = false;
        group = "www-data";
        home = "/var/www";
        useDefaultShell = true;
        createHome = true;
      };
    };

    system.stateVersion = "17.09";

    users.groups.www-data.name = "www-data";

    nix.gc.automatic = true;
  };
}
