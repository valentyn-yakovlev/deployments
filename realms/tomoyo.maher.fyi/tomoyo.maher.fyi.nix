{
  network.description = "tomoyo.maher.fyi";

  tomoyo = { config, lib, pkgs, ... }: let

    sshKeys = import ./../../local/common/ssh-keys.nix;

    secrets = import ./secrets.nix;

    localPackages = (import ./../../local/pkgs/all-packages.nix) {
      inherit config lib pkgs;
    };

in rec {
    imports = [
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

    nix.maxJobs = lib.mkDefault 12;

    powerManagement.cpuFreqGovernor = "powersave";

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
      hostName = "tomoyo.maher.fyi";
      interfaces."eno1".ip4 = [{
        address = "192.168.1.245";
        prefixLength = 24;
      }];
      firewall = {
        enable = true;
        allowedTCPPorts = [
          22 # ssh, sftp
          80 # http
          88 # Kerberos v5
          111 # NFS
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
        127.0.0.1     tomoyo.maher.fyi
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
        zfs
        zfstools
      ] ++ (import ./../../local/common/package-lists/essentials.nix) {
        inherit pkgs localPackages;
      };
    };

    services.openssh.enable = true;
    services.openssh.permitRootLogin = "yes";

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
        isNormalUser = false;
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
    };

    nix.gc.automatic = true;

    system.stateVersion = "17.09";
  };
}
