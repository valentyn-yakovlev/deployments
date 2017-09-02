{ config, lib, pkgs, ... }:
{
  # imports = [] ++ (import ./../../local/modules/module-list.nix);

  nix.binaryCaches = [
    "https://cache.nixos.org/"

    # This assumes that you use the default `nix-serve` port of 5000
    "http://192.168.1.174:5000"
  ];

  nix.binaryCachePublicKeys = [
    "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="

    # Replace the following string with the contents of the
    # `nix-serve.pub` file you generated in the "Server configuration"
    # section above
    "192.168.1.174:U3bKXKu1920ndnh9rG0VCvDlO9pO8BxQ9Dy2b7NWAfA="
  ];

  fileSystems."/" = {
    device = "/dev/mapper/vgroup-root";
    fsType = "ext4";
    options = [ "noatime" "nodiratime" "discard" ];
  };

  fileSystems."/boot" = {
    device = "/dev/disk/by-uuid/A359-6573";
    fsType = "vfat";
  };

  # fileSystems."/tank" = {
  #   options = [
  #     "nofail"
  #     "x-systemd.device-timeout=1"
  #   ];
  #   device = "tank";
  #   fsType = "zfs";
  # };

  hardware.pulseaudio.enable = true;

  swapDevices = [{ device = "/dev/mapper/vgroup-swap"; }];

  nix.maxJobs = lib.mkDefault 8;

  powerManagement.cpuFreqGovernor = "powersave";

  boot = {
    # zfs = {
    #   forceImportAll = false;
    #   forceImportRoot = false;
    # };
    loader = {
      systemd-boot.enable = true;
      efi = {
        canTouchEfiVariables = true;
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
          device = "/dev/disk/by-uuid/1d6b3cc6-56db-4031-9984-e323b83bca59";
          allowDiscards = true;
        }
        # {
        #   name = "crypto_zfs_00";
        #   device = "/dev/disk/by-uuid/1c3851fc-c1de-4860-806f-4609801f5fb9";
        #   preLVM = false;
        #   keyFile = "/root/tank.keyfile";
        # }
        # {
        #   name = "crypto_zfs_01";
        #   device = "/dev/disk/by-uuid/7065dce3-1be4-4cae-b7c2-4dc4e1bf0f23";
        #   preLVM = false;
        #   keyFile = "/root/tank.keyfile";
        # }
      ];
    };
  };

  systemd.generator-packages = [
    pkgs.systemd-cryptsetup-generator
  ];

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
    networkmanager = {
      enable = true;
      packages = [ pkgs.gnome3.networkmanager_openvpn ];
    };
  };

  # services.local--pia-nm.enable = true;

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
    ];
    # etc = {
    #   "crypttab" = {
    #     enable = true;
    #     text = ''
    #       crypto_zfs_00 UUID=a3845124-06b1-4980-93cb-b4b2d3239405 /root/tank.keyfile luks
    #       crypto_zfs_01 UUID=54f9d9f0-20da-4fe6-bcea-7df395cdf7ef /root/tank.keyfile luks
    #     '';
    #   };
    # };
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

  services.xserver = {
    enable = true;
    layout = "us";
    libinput = {
      enable = true;
      tapping = true;
    };
    xkbOptions = "caps:hyper";
    displayManager.lightdm.enable = true;
    desktopManager.plasma5.enable = true;
  };

  services.transmission = {
    enable = true;
    port = 9091;
    # settings = {}
  };

  services.resolved = { enable = true; };

  programs.zsh.enable = true;

  nixpkgs.config.allowUnfree = true;

  security.sudo.wheelNeedsPassword = false;

  users.mutableUsers = false;

  users.users = {
    root = {
      initialPassword = "hunter2";
    };
    eqyiel = {
      isNormalUser = true;
      extraGroups = [ "wheel" "systemd-journal" "www-data" ];
      shell = pkgs.zsh;

      initialPassword = "hunter2";
    };
  };

  nix.gc.automatic = true;

  system.stateVersion = "17.09";
}
