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
    loginAccounts = {
      "ruben@maher.fyi" = (secrets.mailserver.loginAccounts."ruben@maher.fyi") // {
        sieveScript = ''
           require ["fileinto", "mailbox"];

           if address :is "from" "notifications@github.com" {
             fileinto :create "GitHub";
             stop;
           }

           # This must be the last rule, it will check if list-id is set, and
           # file the message into the Lists folder for further investigation
           elsif header :matches "list-id" "<?*>" {
             fileinto :create "Lists";
             stop;
           }
         '';
      };

      "r@rkm.id.au" = (secrets.mailserver.loginAccounts."r@rkm.id.au") // {
        sieveScript = ''
          redirect "ruben@maher.fyi";
          stop;
        '';
      };

      "nadiah@maher.fyi" = (secrets.mailserver.loginAccounts."nadiah@maher.fyi") // {};
    };
    dkimKeyDirectory = "/var/dkim";
    mailDirectory = "/mnt/var/lib/${config.users.users.vmail.name}";
    virtualAliases = {
      "*" = "ruben@maher.fyi";
    };
    enableImap = true;
    enableImapSsl = true;
    debug = true;
  };

  users.users = {
    vmail = {
      home = lib.mkForce "/mnt/var/lib/${config.users.users.vmail.name}";
      createHome = true;
    };
  };

  # don't throw errors because there's no ipv6
  services.dovecot2.extraConfig = ''
    listen = *

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
