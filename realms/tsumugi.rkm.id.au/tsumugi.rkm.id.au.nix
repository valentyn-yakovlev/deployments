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
      # sslProtocols = "TLSv1 TLSv1.1 TLSv1.2";
      appendConfig = ''
        error_log stderr info;
      '';
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
        extraGroups = [ "wheel" "systemd-journal" ];
        shell = pkgs.zsh;
        openssh.authorizedKeys.keys = [
          sshKeys.rkm
        ];
        inherit (secrets.users.users.eqyiel) initialPassword;
      };
      r = { # for sending and receiving email
        isNormalUser = true;
        shell = pkgs.zsh;
        openssh.authorizedKeys.keys = [
          sshKeys.rkm
        ];
        inherit (secrets.users.users.r) initialPassword;
      };
      www-data = {
        isNormalUser = false;
        group = "www-data";
        home = "/var/www";
        useDefaultShell = true;
        createHome = true;
      };
    };

    users.groups.www-data.name = "www-data";

    nix.gc.automatic = true;
  };
}
