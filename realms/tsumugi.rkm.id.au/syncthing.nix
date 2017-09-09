{ config, lib, pkgs, ... }:

let

  hostname = "syncthing.rkm.id.au";
  robotsTxt = pkgs.writeText "robots.txt" ''
    User-agent: *
    Disallow: /
  '';

in rec {
  networking.firewall.allowedTCPPorts = [ 22000 ];
  networking.firewall.allowedUDPPorts = [ 21027 ];

  services.nginx.virtualHosts = {
    "${hostname}" = {
      onlySSL = true;
      enableACME = true;
      locations = {
        "/robots.txt" = {
          extraConfig = ''
            alias ${robotsTxt};
          '';
        };
        "/" = {
          proxyPass = "http://127.0.0.1:8384";
        };
      };
    };
  };

  services.syncthing = {
    user = "eqyiel";
    group = "users";
    dataDir = "/var/lib/syncthing";
    enable = true;
    useInotify = false;
  };

  systemd.services.syncthing-startup = {
    before = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = rec {
      ExecStart = pkgs.writeScript "syncthing-startup" ''
        #! ${pkgs.bash}/bin/bash
        SYNCTHING_DATADIR="${services.syncthing.dataDir}"
        if (! test -e "''${SYNCTHING_DATADIR}"); then
          mkdir -p "''${SYNCTHING_DATADIR}"
          chown ${services.syncthing.user}:${services.syncthing.group} \
             "''${SYNCTHING_DATADIR}"
        fi
      '';
    };
    enable = true;
  };
}
