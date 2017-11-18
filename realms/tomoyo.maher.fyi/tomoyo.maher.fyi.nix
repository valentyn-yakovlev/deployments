{
  network.description = "tomoyo.maher.fyi";

  # Keep a GC root for the build
  network.enableRollback = true;

  tomoyo = { config, lib, pkgs, ... }: let

    sshKeys = import ./../../local/common/ssh-keys.nix;

    commonAcmeConfig = ./../../local/common/acme-config.nix;

    secrets = import ./secrets.nix;

    localPackages = (import ./../../local/pkgs/all-packages.nix) {
      inherit config lib pkgs;
    };

in rec {
    imports = [
      ./lib
      ./config
      ./../../local/pkgs/overrides.nix
    ] ++ (import ./../../local/modules/module-list.nix);

    fileSystems."/" = {
      device = "/dev/mapper/vgroup-root";
      fsType = "ext4";
      options = [ "noatime" "nodiratime" "discard" ];
    };

    fileSystems."/boot" = {
      device = "/dev/disk/by-uuid/904D-D5B6";
      fsType = "vfat";
    };

    # To create new zfs "filesystems":
    #
    # $ zfs create -o mountpoint=legacy tank/name-of-the-filesystem
    # $ zfs set atime=off tank/name-of-the-filesystem
    fileSystems."/mnt/media" = {
      options = [
        "nofail"
        "x-systemd.device-timeout=1"
      ];
      device = "tank/media";
      fsType = "zfs";
    };

    fileSystems."/mnt/var" = {
      options = [
        "nofail"
        "x-systemd.device-timeout=1"
      ];
      device = "tank/var";
      fsType = "zfs";
    };

    fileSystems."/mnt/home" = {
      options = [
        "nofail"
        "x-systemd.device-timeout=1"
      ];
      device = "tank/home";
      fsType = "zfs";
    };

    hardware.pulseaudio.enable = true;

    hardware.enableAllFirmware = true;

    swapDevices = [{ device = "/dev/mapper/vgroup-swap"; }];

    powerManagement = {
      enable = true;
      cpuFreqGovernor = "powersave";
    };

    boot = {
      zfs = {
        forceImportAll = false;
        forceImportRoot = false;
      };
      loader = {
        systemd-boot.enable = true;
        efi.canTouchEfiVariables = true;
      };
      cleanTmpDir = true;
      extraModulePackages = [ ];
      kernelModules = [ "kvm-intel" ];
      kernelParams = [ "ipv6.disable=1" ];
      supportedFilesystems = [ "zfs" "nfs" ];
      initrd = {
        # network = {
        #   enable = true;
        #   ssh = {
        #     hostRSAKey = '''';
        #     authorizedKeys = [];
        #   };
        # };
        availableKernelModules = [
          "xhci_pci"
          "ehci_pci"
          "ahci"
          "megaraid_sas"
          "mpt3sas"
          "usbhid"
          "usb_storage"
          "sd_mod"
        ];
        luks.devices = [
          {
            name = "root";
            device = "/dev/disk/by-uuid/73c542e6-19af-4f50-b0cb-823294a8390d";
            allowDiscards = true;
          }
          {
            name = "crypto_zfs_00";
            device = "/dev/disk/by-uuid/2e59e4cf-cfb2-42dd-9bdb-b6da0f031c18";
            preLVM = false;
          }
          {
            name = "crypto_zfs_01";
            device = "/dev/disk/by-uuid/1c634e3c-05aa-4b86-91c4-2a309c5475a6";
            preLVM = false;
          }
        ];
      };
    };

    networking = {
      # required for ZFS, generate with
      # cksum /etc/machine-id | while read c rest; do printf "%x" $c; done
      # or
      # head -c4 /dev/urandom | od -A none -t x4
      hostId = "0f4dc8dd";
      hostName = "maher.fyi";
      defaultGateway = "114.111.153.1";
      nameservers = [ "122.100.13.50" "111.125.175.50" ];
      interfaces."eno1".ip4 = [
        { # ptr -> maher.fyi
          address = "114.111.153.166";
          prefixLength = 24;
        }
        { # ptr -> shitpost.digital
          address = "114.111.153.167";
          prefixLength = 24;
        }
        { # ptr -> rsvp.fyi
          address = "114.111.153.168";
          prefixLength = 24;
        }
        { # ptr -> rkm.id.au
          address = "114.111.153.169";
          prefixLength = 24;
        }
      ];
      enableIPv6 = false;
      firewall = {
        enable = true;
        allowedTCPPorts = [
          22 # ssh, sftp
          80 # http
          88 # Kerberos v5
          111 # NFS
          443 # HTTPS
          2049 # NFS
        ];
        allowedUDPPorts = [
          88 # Kerberos v5
          111 # NFS
          2049 # NFS
        ];
        trustedInterfaces = [];
        logRefusedPackets = true;
      };
      extraHosts = ''
        127.0.0.1 tomoyo.maher.fyi
      '';
    };

    i18n = {
      consoleFont = "Lat2-Terminus16";
      consoleKeyMap = "us";
      defaultLocale = "en_US.UTF-8";
    };

    time.timeZone = "Australia/Adelaide";

    environment = {
      systemPackages = with pkgs; [
        lm_sensors
        zfs
        zfstools
      ] ++ (import ./../../local/common/package-lists/essentials.nix) {
        inherit pkgs localPackages;
      };
    };

    services.zfs.autoSnapshot.enable = true;

    services.openssh.enable = true;
    services.openssh.permitRootLogin = "yes";

    services.hydra = {
      enable = true;
      useSubstitutes = true;
      hydraURL = "https://hydra.maher.fyi";
      notificationSender = "hydra@maher.fyi";
    };

    services.nginx = {
      enable = true;
      appendConfig = ''
        error_log stderr info;
      '';
      virtualHosts = {
        "maher.fyi" =  {
          forceSSL = true;
          enableACME = true;
        };

        "cloud.maher.fyi" =  {
          forceSSL = true;
          enableACME = true;
        };

        "hydra.maher.fyi" =  {
          forceSSL = true;
          enableACME = true;
          locations = {
            "/" = {
              proxyPass = "http://localhost:3000";
              extraConfig = ''
                proxy_set_header Host $http_host;
                proxy_set_header REMOTE_ADDR $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto https;
              '';
            };
          };
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

    services.fail2ban.enable = true;

    services.pcscd.enable = true;

    services.smartd.enable = true;

    services.openntpd = {
      enable = true;
      servers = [
        "0.au.pool.ntp.org"
	      "1.au.pool.ntp.org"
	      "2.au.pool.ntp.org"
	      "3.au.pool.ntp.org"
      ];
    };

    services.prometheus = {
      nodeExporter = {
        enable = true;
        enabledCollectors = [
          "systemd"
          "diskstats"
          "filesystem"
          "loadavg"
          "meminfo"
          "netdev"
          "netstat"
          "stat"
          "time"
          "uname"
        ];
        openFirewall = false; # using proxyPass
      };
    };

    services.resolved = { enable = true; };

    programs.zsh.enable = true;

    nixpkgs.config.allowUnfree = true;

    security.sudo.wheelNeedsPassword = false;

    users.mutableUsers = false;

    users.users = {
      root = {
        shell = pkgs.zsh;
        openssh.authorizedKeys.keys = [
         sshKeys.rkm
       ];
       inherit (secrets.users.users.root) initialPassword;
     };

      eqyiel = {
        home = "/mnt/home/${config.users.users.eqyiel.name}";
        isNormalUser = true;
        isSystemUser = false;
        extraGroups = [
          "wheel"
          "${config.users.groups.systemd-journal.name}"
        ];
        shell = pkgs.zsh;
        openssh.authorizedKeys.keys = [
          sshKeys.rkm
        ];
        inherit (secrets.users.users.eqyiel) initialPassword;
      };

      nix-builder = {
        isNormalUser = true;
        useDefaultShell = true;
        home = "/var/lib/${config.users.users.nix-builder.name}";
        createHome = true;
        openssh.authorizedKeys.keys = [
          sshKeys.rkm sshKeys.nix-builder
        ];
        inherit (secrets.users.users.nix-builder) initialPassword;
      };
    };

    nix = {
      buildMachines = [{
        hostName = "localhost";
        systems = [ "x86_64-linux" ];
        maxJobs = 12;
        supportedFeatures = [ "kvm" "nixos-test" ];
      }];
      trustedUsers = [ "root" "nix-builder" ];
      gc = {
        automatic = true;
        dates = "monthly";
        options = "--delete-older-than 31d";
      };
      sshServe.enable = true;
      sshServe.keys = [ sshKeys.rkm ];
      maxJobs = lib.mkDefault 12;
    };

    system.stateVersion = "18.03";
  };
}

# Local Variables:
# mode: nix
# End:
