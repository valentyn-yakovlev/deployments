{ config, lib, pkgs, ... }:

let
  secrets = import ./secrets.nix;

  fqdn = "maher.fyi";
in {
  networking.firewall = {
    allowedTCPPorts = [
      3478 # coturn
      8448 # matrix
    ];
    allowedUDPPorts = [
      3478 # coturn
    ];
    allowedUDPPortRanges = [
      { from = 49152; to = 65535; } # coturn
    ];
    trustedInterfaces = [ "lo" ];
  };

  services.matrix-synapse = {
    dataDir = "/mnt/var/lib/matrix-synapse";
    allow_guest_access = false;
    bcrypt_rounds = "12";
    enable = true;
    web_client = false;
    enable_registration = true;
    registration_shared_secret = secrets.services.matrix-synapse.registration_shared_secret;
    server_name = fqdn;
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
      "turn:${fqdn}:3478?transport=udp"
      "turn:${fqdn}:3478?transport=tcp"
    ];
    # This needs to be the same as services.coturn.static-auth-secret
    turn_shared_secret = secrets.services.matrix-synapse.turn_shared_secret;
    turn_user_lifetime = "24h";
    url_preview_enabled = true;
  };

  services.coturn = {
    enable = true;
    lt-cred-mech = true;
    static-auth-secret = secrets.services.coturn.static-auth-secret;
    realm = fqdn;
    cert = "/var/lib/acme/${fqdn}/fullchain.pem";
    pkey = "/var/lib/acme/${fqdn}/key.pem";
    min-port = 49152;
    max-port = 65535;
  };

  services.postgresql.enable = true;

  services.nginx = {
    enable = true;
    virtualHosts = {
      "maher.fyi" = {
        forceSSL = true;
        enableACME = true;
        locations = {
          "/_matrix" = {
            proxyPass = "https://127.0.0.1:8448/_matrix";
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

  # This is not necessary if acme is enabled elsewhere for this fqdn.
  # services.nginx = {
  #   enable = true;
  #   virtualHosts."${fqdn}" = {
  #     serverName = fqdn;
  #     forceSSL = true;
  #     enableACME = true;
  #     acmeRoot = "/var/lib/acme/acme-challenge";
  #   };
  # };

  security.acme.certs."${fqdn}".postRun = "systemctl reload-or-restart matrix-synapse coturn";
}
