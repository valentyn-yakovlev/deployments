# logical specification
{
  network.description = "hoshijiro.maher.fyi";

  hoshijiro = { config, lib, pkgs, ... }: let

    sshKeys = import ./../../local/common/ssh-keys.nix;

    secrets = import ./secrets.nix;

    localPackages = (import ./../../local/pkgs/all-packages.nix) {
      inherit config lib pkgs;
    };

  in {
    fileSystems."/" = {
      device = "/dev/mapper/vgroup-root";
      fsType = "ext4";
      options = [ "noatime" "nodiratime" "discard" ];
    };

    fileSystems."/boot" = {
      device = "/dev/disk/by-uuid/6BA3-207D";
      fsType = "vfat";
    };

    swapDevices = [{ device = "/dev/mapper/vgroup-swap"; }];

    nix.maxJobs = lib.mkDefault 8;

    powerManagement.cpuFreqGovernor = "powersave";

    boot = {
      zfs = {
        forceImportAll = false;
        forceImportRoot = false;
      };
      loader = {
        systemd-boot.enable = true;
        efi = {
          canTouchEfiVariables = true;
          efiSysMountPoint = "/boot/efi";
        };
      };
      cleanTmpDir = true;
      extraModulePackages = [ ];
      kernelModules = [ "kvm-intel" ];
      supportedFilesystems = [ "zfs" ];
      initrd = {
        availableKernelModules = [
          "xhci_pci"
          "ehci_pci"
          "ahci"
          "firewire_ohci"
          "usbhid"
          "usb_storage"
          "sd_mod"
        ];
        luks.devices = [
          {
            name = "root";
            device = "/dev/disk/by-uuid/44fc1f47-19f1-43b7-ad42-379e945dcc4d";
            allowDiscards = true;
          }
          {
            name = "crypto_zfs_00";
            device = "/dev/disk/by-uuid/a3845124-06b1-4980-93cb-b4b2d3239405";
            preLVM = false;
            keyFile = "/root/tank.keyfile";
          }
          {
            name = "crypto_zfs_01";
            device = "/dev/disk/by-uuid/54f9d9f0-20da-4fe6-bcea-7df395cdf7ef";
            preLVM = false;
            keyFile = "/root/tank.keyfile";
          }
        ];
      };
    };

    networking = {
      # required for ZFS, generate with
      # cksum /etc/machine-id | while read c rest; do printf "%x" $c; done
      # or
      # head -c4 /dev/urandom | od -A none -t x4
      hostId = "63737ac9";
      hostName = "hoshijiro.maher.fyi";
      interfaces."eno1".ip4 = [{
        address = "192.168.1.215";
        prefixLength = 24;
      }];
      firewall = {
        enable = true;
        allowedTCPPorts = [
          22 # ssh, sftp
        ];
        allowedUDPPorts = [];
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
        zfs
        zfstools
        mpv
        firefox
        chromium
        hplip
        libreoffice
        python27Packages.syncthing-gtk
      ] ++ (import ./../../local/common/package-lists/essentials.nix) {
        inherit pkgs localPackages;
      };
    };

    services.openssh.enable = true;
    services.openssh.permitRootLogin = "yes";

    services.fail2ban.enable = true;

    services.pcscd.enable = true;

    services.smartd.enable = true;

    services.zfs = {
      autoScrub = { enable = true; interval = "daily"; };
      autoSnapshot = {
        enable = true;
        flags = "-k -p --utc";
        daily = 7;
        frequent = 4;
        hourly = 24;
        monthly = 12;
        weekly = 4;
      };
    };

    services.xserver.enable = true;

    services.xserver.displayManager.sddm.enable = true;

    services.xserver.desktopManager.plasma5.enable = true;

    programs.zsh.enable = true;

    nixpkgs.config.allowUnfree = true;

    security.sudo.wheelNeedsPassword = false;

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
    };

    nix.gc.automatic = true;

    system.stateVersion = "17.09";
  };
}
