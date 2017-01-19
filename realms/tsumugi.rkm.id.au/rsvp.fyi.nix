{ config, lib, pkgs, ... }:

let

  secrets = import ./secrets.nix;
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
  pgUser = "rsvp.fyi";
  pgDatabase = "rsvp.fyi";
  pgPassword = secrets.pgPassword;
  pgPort = "5432";
  pgHost = "127.0.0.1";
  serverHost = "127.0.0.1";
  serverPassword = secrets.serverPassword;
  serverPort = 12344;
  serverPkg = localPackages.nodePackages."rsvp.fyi-server";

in {
  services.nginx.virtualHosts =
    let
      virtualhostConfig = {
        enableSSL = true;
        forceSSL = true;
        enableACME = true;
        locations = {
          "/robots.txt" = {
            extraConfig = ''
              alias ${robotsTxt};
            '';
          };
          "/api" = {
            proxyPass = "http://127.0.0.1:12344";
          };
          "/" = {
            root = documentRoot;
            index = "index.html";
          };
        };
      };
    in {
      "${hostname}" = virtualhostConfig;
      "staging.${hostname}" = virtualhostConfig;
      "www.${hostname}" = {
        enableACME = true;
        enableSSL = true;
        locations = {
          "/" = {
            extraConfig = "return 301 https://${hostname};";
          };
        };
      };
    };

  services.postgresql.enable = true;

  systemd.services."${hostname}-server" = {
     after = [ "network.target" "nginx.service" "postgresql.service" ];
     environment = {
       PGUSER = "${pgUser}";
       PGDATABASE = "${pgDatabase}";
       PGPASSWORD = "${pgPassword}";
       PGPORT = "${toString pgPort}";
       PGHOST = "${pgHost}";
       PGMAXCLIENTS = "10";
       PGIDLETIMEOUTMILLIS = "30000";
       HOST = "${serverHost}";
       PORT = "${toString serverPort}";
       PASSWORD = "${serverPassword}";
     };
     serviceConfig = {
       Type = "simple";
       Restart = "always";
       RestartSec = "300";
       ExecStart = "${serverPkg}/bin/rsvp.fyi-server";
     };
     enable = true;
  };
}
