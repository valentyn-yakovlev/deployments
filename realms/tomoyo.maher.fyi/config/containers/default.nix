{ config, lib, pkgs, ... }:

with lib;

rec {
  services.nginx = {
    enable = true;
    virtualHosts = let
      hanabiRedirectConfig = {
      forceSSL = true;
      enableACME = true;
      globalRedirect = "hannahgoat.com";
    };
    in {
        "hannahgoat.com" = {
          forceSSL = true;
          enableACME = true;
          locations = {
            "/" = {
              proxyPass = "http://hanabi.containers";
              extraConfig = ''
                proxy_set_header X-Real-IP  $remote_addr;
                proxy_set_header X-Forwarded-For $remote_addr;
                proxy_set_header Host $host;
              '';
            };
          };
        };
        "www.hannahgoat.com" = {} // hanabiRedirectConfig;
        "hannah-blake.com" = {} // hanabiRedirectConfig;
        "www.hannah-blake.com" = {} // hanabiRedirectConfig;
      };
    };


  users.users = {
    hanabi = {
      home = "/mnt/home/${config.users.users.hanabi.name}";
      isNormalUser = true;
      isSystemUser = false;
    };
  };

  containers.hanabi = {
    autoStart = true;
    privateNetwork = true;
    hostAddress = "192.168.102.10";
    localAddress = "192.168.102.11";
    bindMounts = {
      "${config.users.users.hanabi.home}" = {
        hostPath = "${config.users.users.hanabi.home}";
        isReadOnly = false;
        mountPoint = "/data";
      };
    };
    config = (import ./hanabi.nix { inherit config lib pkgs; });
  };
}
