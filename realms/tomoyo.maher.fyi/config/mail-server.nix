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
    enableImap = true;
    enableImapSsl = true;
    debug = true;
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

    auth_debug_passwords = yes

    # k-9 mail chews through these
    mail_max_userip_connections = 50

    namespace inbox {
      inbox = yes
      separator = /

      mailbox Spam {
        auto = subscribe
        special_use = \Junk
      }

      mailbox Trash {
        auto = subscribe
        special_use = \Trash
      }

      mailbox Drafts {
        auto = subscribe
        special_use = \Drafts
      }

      mailbox Sent {
        auto = subscribe
        special_use = \Sent
      }

      mailbox Archive {
        auto = subscribe
        special_use = \Archive
      }
    }
  '';

  services.postfix.extraConfig = ''
    inet_protocols = ipv4
  '';
}
