# logical specification
{
  network.description = "hoshijiro.maher.fyi";

  hoshijiro = { config, lib, pkgs, ... }: let

    sshKeys = import ./../../local/common/ssh-keys.nix;

    secrets = import ./secrets.nix;

    localPackages = (import ./../../local/pkgs/all-packages.nix) {
      inherit config lib pkgs;
    };

in rec {
    imports = [] ++ (import ./../../local/modules/module-list.nix);

    fileSystems."/" = {
      device = "/dev/mapper/vgroup-root";
      fsType = "ext4";
      options = [ "noatime" "nodiratime" "discard" ];
    };

    fileSystems."/boot" = {
      device = "/dev/disk/by-uuid/A359-6573";
      fsType = "vfat";
    };

    fileSystems."/mnt/media" = {
      options = [
        "nofail"
        "x-systemd.device-timeout=1"
      ];
      device = "tank/media";
      fsType = "zfs";
    };

    fileSystems."/mnt/transmission" = {
      options = [
        "nofail"
        "x-systemd.device-timeout=1"
      ];
      device = "tank/transmission";
      fsType = "zfs";
    };

    hardware.pulseaudio.enable = true;

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
        efi.canTouchEfiVariables = true;
      };
      cleanTmpDir = true;
      extraModulePackages = [ ];
      kernelModules = [ "kvm-intel" ];
      supportedFilesystems = [ "zfs" ];
      initrd = {
        network = {
          enable = true;
          ssh = {
            hostRSAKey = '''';
            authorizedKeys = [];
          };
        };
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
          # Keyfile doesn't work here right now, see the nixpkgs issue about
          # single password unlocking.
          #
          # The crypttab generator does though, which is an OK workaround if you
          # don't actually need these devices for boot.
          #
          # Unfortunately it doesn't seem to work with ZFS, even if it's used
          # for non-root partitions.
          #
          # This means you have to enter a passphrase for each of these devices
          # during boot.  😿
          {
            name = "crypto_zfs_00";
            device = "/dev/disk/by-uuid/1c3851fc-c1de-4860-806f-4609801f5fb9";
            preLVM = false;
            # keyFile = "/root/tank.keyfile";
          }
          {
            name = "crypto_zfs_01";
            device = "/dev/disk/by-uuid/7065dce3-1be4-4cae-b7c2-4dc4e1bf0f23";
            preLVM = false;
            # keyFile = "/root/tank.keyfile";
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
          80 # http
        ];
        allowedUDPPorts = [];
        trustedInterfaces = [ "lo" ];
        extraCommands = ''
          for chain in \
            restrict-users-tun-input \
            restrict-users-tun-output; do
            ip46tables \
              --flush "''${chain}" \
              2>/dev/null || true
            ip46tables \
              --delete-chain "''${chain}" \
              2>/dev/null || true
          done

          ip46tables --new-chain restrict-users-tun-input
          ip46tables --new-chain restrict-users-tun-output

          # Allow transmission to serve its web client on the loopback interface
          ip46tables \
            --append restrict-users-tun-output \
            --match owner \
            --uid-owner ${config.users.users.transmission.name} \
            --out-interface lo \
            --source-port ${toString config.services.transmission.port}\
            --jump ACCEPT

          # Allow transmission to serve its web client on the loopback interface
          ip46tables \
            --append restrict-users-tun-input \
            --match owner \
            --uid-owner ${config.users.users.transmission.name} \
            --out-interface lo \
            --destination-port ${toString config.services.transmission.port}\
            --jump ACCEPT

          # DROP any packet which is going to be sent by this --uid-owner if
          # it is for any --out-interface whose name does not (\!) start with
          # "tun".
          for user in \
            ${config.users.users.transmission.name} \
            ${config.users.users.eqyiel.name}; do
            ip46tables \
              --append restrict-users-tun-output \
              --match owner \
              --uid-owner "''${user}"
              ! --out-interface tun+ \
              --jump DROP
          done

          # DROP any packet which is going to be sent by this --uid-owner if
          # it is for any --in-interface whose name does not (\!) start with
          # "tun".
          ip46tables \
            --append restrict-users-tun-output \
            --match owner \
            --uid-owner "''${user}"
            ! --out-interface tun+ \
            --jump DROP

          # Enable the chains
          ip46tables \
            --append INPUT \
            --jump restrict-users-tun-input
          ip46tables \
            --append OUTPUT \
            --jump restrict-users-tun-output
        '';
        extraStopCommands = ''
          for chain in \
            restrict-users-tun-input \
            restrict-users-tun-output; do
            ip46tables \
              --flush "''${chain}" \
              2>/dev/null || true
            ip46tables \
              --delete-chain "''${chain}" \
              2>/dev/null || true
          done
        '';
      };
      networkmanager = {
        enable = true;
        packages = [ pkgs.gnome3.networkmanager_openvpn ];
        dispatcherScripts = [
          # Each script receives two arguments, the first being the interface name
          # of the device an operation just happened on, and second the action.
          #
          # See: man 8 networkmanager
          { # Update transmission's port forwarding assignment
            type = "basic";
            source = pkgs.writeScript "update-transmission-port-forwarding-assignment" ''
              #!${pkgs.bash}/bin/bash

              set -euo pipefail

              INTERFACE="''${1}"
              ACTION="''${2}"

              TEMP_FILE="$(${pkgs.coreutils}/bin/mktemp)"

              cleanup() {
                ${pkgs.coreutils}/bin/rm "''${TEMP_FILE}"
              }

              trap 'cleanup' EXIT

              if [[ "''${ACTION}" == "vpn-up" ]]; then
                CONFIG_FILE="${config.users.users.transmission.home}/.config/transmission-daemon/settings.json"
                PORT="$(${localPackages.get-pia-port-forwarding-assignment}/bin/get-pia-port-forwarding-assignment | ${pkgs.jq}/bin/jq '.port')"
                echo "Rewritten config: $(${pkgs.jq}/bin/jq --arg PORT "''${PORT}" '.["peer-port"] = $PORT')"
                ${pkgs.jq}/bin/jq --arg PORT "''${PORT}" '.["peer-port"] = $PORT' < "''${CONFIG_FILE}" > "''${TEMP_FILE}"

                echo "Received port assignment of ''${PORT} for ''${INTERFACE}, reloading transmission daemon."

                ${pkgs.coreutils}/bin/mv "''${TEMP_FILE}" "''${CONFIG_FILE}"
                ${pkgs.coreutils}/bin/chmod 600 "''${CONFIG_FILE}"
                ${pkgs.coreutils}/bin/chown transmission:transmission "''${CONFIG_FILE}"

                ${pkgs.systemd}/bin/systemctl reload transmission.service
              fi
            '';
          }
        ];
      };
    };

    services.local--pia-nm.enable = true;

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
      etc = {
        "xdg/gtk-3.0/settings.ini" = {
          text = ''
            [Settings]
            gtk-key-theme-name = Emacs
          '';
        };
      };
    };

    services.nginx = {
      enable = true;
      virtualHosts = {
        "_" = {
          default = true;
          locations = let
            transmissionPort = toString config.services.transmission.port;
          in {
            "/transmission" = {
              extraConfig = ''
                proxy_set_header        Host $host;
                proxy_set_header        X-Real-IP $remote_addr;
                proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header        X-Forwarded-Proto $scheme;
              '';
              proxyPass = "http://localhost:${transmissionPort}";
            };

            "/transmission/rpc" = {
              proxyPass = "http://localhost:${transmissionPort}";
            };

            "/transmission/web/" = {
              proxyPass = "http://localhost:${transmissionPort}";
            };

            "/transmission/upload" = {
              proxyPass = "http://localhost:${transmissionPort}";
            };

            "/transmission/web/style/" = {
              alias = "${pkgs.transmission}/share/transmission/web/style/";
            };

            "/transmission/web/javascript/" = {
              alias = "${pkgs.transmission}/share/transmission/web/javascript/";
            };

            "/transmission/web/images/" = {
              alias = "${pkgs.transmission}/share/transmission/web/images/";
            };
          };
        };
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

    services.xserver = {
      enable = true;
      layout = "us";
      libinput = {
        enable = true;
        tapping = true;
      };
      xkbOptions = "caps:hyper";
      displayManager.gdm = {
        enable = true;
        autoLogin = {
          enable = true;
          user = "eqyiel";
        };
      };
      desktopManager.gnome3 = {
        enable = true;
      };
    };

    services.transmission = {
      enable = true;
      port = 9091;
      # try binding for tun interface
      settings = {
        download-dir = "/mnt/transmission/download-dir";
        incomplete-dir = "/mnt/transmission/incomplete-dir";
        incomplete-dir-enabled = true;
        rpc-whitelist = "127.0.0.1,192.168.*.*";
        rpc-whitelist-enabled = true;
        ratio-limit-enabled = true;
        ratio-limit = "2.0";
        upload-limit = "100";
        upload-limit-enabled = true;
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
        isNormalUser = true;
        extraGroups = [
          "wheel"
          "${config.users.groups.systemd-journal.name}"
          "${config.users.users.transmission.group}"
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
