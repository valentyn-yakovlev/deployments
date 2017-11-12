{ config, lib, pkgs, ... }:

let
  secrets = (import ./secrets.nix);
in {
  imports = [ ../lib ];

  environment.systemPackages = with pkgs; [ mkpasswd ];

  mailserver = {
    enable = true;
    fqdn = "maher.fyi";
    domains = [ "maher.fyi" "rkm.id.au" ];
    vmailUserName = "vmail";
    vmailGroupName = "vmail";
    certificateScheme = 3;
    loginAccounts = secrets.mailserver.loginAccounts;
    dkimKeyDirectory = "/var/dkim";
    mailDirectory = "/mnt/home/${config.users.users.vmail.name}";
    virtualAliases = {
      "*" = "ruben@maher.fyi";
    };
  };

  users.users = {
    vmail = {
      home = lib.mkForce "/mnt/home/${config.users.users.vmail.name}";
      createHome = true;
    };
  };

  # don't throw errors because there's no ipv6
  services.dovecot2.extraConfig = ''
    listen = *
  '';

  services.postfix.extraConfig = ''
    inet_protocols = ipv4
  '';
}
