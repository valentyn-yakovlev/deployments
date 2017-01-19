{ config, lib, pkgs, ... }:
let

documentRoot = "/var/www/rsvp.fyi";
serverRoot = "/var/lib/rsvp.fyi";
hostname = "rsvp.fyi";
commonAcmeConfig = (import ./common-acme-config.nix).commonAcmeConfig;
robotsTxt = pkgs.writeText "robots.txt" ''
  User-agent: *
  Disallow: /
'';
localPackages = (import ./../../local/pkgs/all-packages.nix) {
  inherit config lib pkgs;
};

in {
  security.acme.certs."rsvp.fyi" = commonAcmeConfig // {
    extraDomains = {
      "www.rsvp.fyi" = null;
    };
    postRun = "systemctl reload-or-restart nginx";
  };

  services.nginx.virtualHosts."${hostname}" = {
    enableSSL = true;
    forceSSL = true;
    sslCertificate = "/var/lib/acme/${hostname}/fullchain.pem";
    sslCertificateKey = "/var/lib/acme/${hostname}/key.pem";
    locations = {
      "/robots.txt" = {
        extraConfig = ''
          alias ${robotsTxt};
        '';
      };
      "/api" = {
        proxyPass = "localhost:12344";
      };
      "/" = {
        root = documentRoot;
        index = "index.html";
      };
    };
  };

  services.postgresql.enable = true;

  systemd.services."${hostname}-server" = {
     after = [ "network.target" "nginx.service" "postgresql.service" ];
     serviceConfig = {
       Restart = "always";
       RestartSec = "300";
       ExecStart = pkgs.writeScript "${hostname}-server-startup" ''
         PGUSER="rsvpfyi" \
           PGDATABASE="rsvp.fyi" \
           PGPASSWORD="hunter2" \
           PGPORT="5432" \
           PGHOST="127.0.0.1" \
           PGMAXCLIENTS="10" \
           PGIDLETIMEOUTMILLIS="30000" \
           HOST="127.0.0.1" \
           PORT="12344" \
           PASSWORD="hunter2" \
           ${localPackages.rsvp-fyi-server}/bin/index.js
         '';
     };
     enable = true;
  };
}
