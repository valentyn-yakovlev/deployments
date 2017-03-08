# Don't forget to open ports 993 (imaps), 25 (smtp) and 587 (smtps)!

# todo: run sa-update periodically

{ config, lib, pkgs, ... }:
let

virtualMailUser = "vmail";
virtualMailGroup = "vmail";
hostname = "rkm.id.au";
commonAcmeConfig = (import ./common-acme-config.nix).commonAcmeConfig;
opendkimStateDir = "/etc/nixos/opendkim";
opendkimRuntimeDir = "/run/opendkim";

in rec {
   services.postfix =
   let
     # https://www.void.gr/kargig/blog/2013/11/24/anonymize-headers-in-postfix/
     smtpHeaderChecks = pkgs.writeText "smtp_header_checks" ''
       /^\s*(Received: from)[^\n]*(.*)/ REPLACE $1 [127.0.0.1] (localhost [127.0.0.1])$2
       /^\s*User-Agent/        IGNORE
       /^\s*X-Enigmail/        IGNORE
       /^\s*X-Mailer/          IGNORE
       /^\s*X-Originating-IP/  IGNORE
     '';
   in {
     enable = true;
     user = virtualMailUser;
     group = virtualMailGroup;
     domain = "mail.${hostname}";
     hostname = "mail.${hostname}";
     sslCACert = "/var/lib/acme/mail.${hostname}/fullchain.pem";
     sslCert = "/var/lib/acme/mail.${hostname}/cert.pem";
     sslKey = "/var/lib/acme/mail.${hostname}/key.pem";
     recipientDelimiter = "+";
     destination = [ "yourdomain.tld" "mail.yourdomain.tld" ];
     virtual = ''
       onealias@yourdomain.tld youruser
       anotheralias@yourdomain.tld youruser
    '';
    extraMasterConf = ''
      smtp  inet  n - n - 1 postscreen
        -o smtpd_sasl_auth_enable=no
      smtpd pass  - - n - - smtpd
        -o smtpd_sasl_auth_enable=no
      dnsblog unix  - - n - 0 dnsblog
      tlsproxy  unix  - - n - 0 tlsproxy
      submission  inet  n - n - - smtpd
        -o syslog_name=postfix/submission
        -o smtpd_tls_security_level=encrypt
        -o smtpd_sasl_auth_enable=yes
        -o smtpd_sasl_type=dovecot
        -o smtpd_sasl_path=inet:127.0.0.1:2847
        -o smtpd_sasl_security_options=noanonymous
        -o smtpd_relay_restrictions=reject_non_fqdn_recipient,reject_unknown_recipient_domain,permit_mynetworks,permit_sasl_authenticated,reject
        -o smtpd_sender_restrictions=permit_mynetworks,reject_non_fqdn_sender,permit_sasl_authenticated,reject
        -o smtpd_client_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
        -o smtpd_helo_required=no
        -o smtpd_helo_restrictions=
        -o milter_macro_daemon_name=ORIGINATING
        -o cleanup_service_name=submission-header-cleanup
      submission-header-cleanup unix  n - n - 0 cleanup
        -o header_checks=pcre:${smtpHeaderChecks}
    '';
     extraConfig = ''
       maximal_queue_lifetime = 1h
       bounce_queue_lifetime = 1h
       maximal_backoff_time = 15m
       minimal_backoff_time = 5m
       queue_run_delay = 5m

       tls_ssl_options = NO_COMPRESSION
       tls_high_cipherlist = EDH+CAMELLIA:EDH+aRSA:EECDH+aRSA+AESGCM:EECDH+aRSA+SHA256:EECDH:+CAMELLIA128:+AES128:+SSLv3:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!IDEA:!ECDSA:kEDH:CAMELLIA128-SHA:AES128-SHA
       smtp_tls_security_level = dane
       smtp_dns_support_level = dnssec
       smtp_tls_session_cache_database = btree:''${data_directory}/smtp_scache
       smtp_tls_protocols = !SSLv2, !SSLv3
       smtp_tls_ciphers = high
       smtpd_tls_security_level = may
       smtpd_tls_protocols = !SSLv2, !SSLv3
       smtpd_tls_ciphers = high
       smtpd_tls_eecdh_grade = strong
       smtpd_tls_dh1024_param_file=/var/lib/dhparams/mail.${hostname}/dhparams.pem
       smtpd_tls_session_cache_database = btree:''${data_directory}/smtpd_scache

       smtpd_relay_restrictions =
                                       reject_non_fqdn_recipient
                                       reject_unknown_recipient_domain
                                       permit_mynetworks
                                       reject_unauth_destination
       smtpd_client_restrictions =     permit_mynetworks
                                       reject_unknown_client_hostname
       smtpd_helo_required = yes
       smtpd_helo_restrictions =   permit_mynetworks
                                   reject_invalid_helo_hostname
                                   reject_non_fqdn_helo_hostname
                                   reject_unknown_helo_hostname
       smtpd_data_restrictions = reject_unauth_pipelining


       mailbox_transport = lmtp:inet:127.0.0.1:8458

       milter_default_action = accept
       milter_protocol = 2
       smtpd_milters = unix:${opendkimRuntimeDir}/opendkim.sock
       non_smtpd_milters = unix:${opendkimRuntimeDir}/opendkim.sock

       # Postscreen
       postscreen_access_list =  permit_mynetworks
       postscreen_blacklist_action = drop
       postscreen_greet_action = drop

       # DNS blocklists
       postscreen_dnsbl_threshold = 2
       postscreen_dnsbl_sites = dnsbl.sorbs.net*1, bl.spamcop.net*1, ix.dnsbl.manitu.net*2, zen.spamhaus.org*2
       postscreen_dnsbl_action = drop

       # turn off biff notifications for performance
       biff = no

       append_dot_mydomain = no
    '';
  };

  security.acme.certs."mail.${hostname}" = commonAcmeConfig // {
    postRun = "systemctl reload-or-restart nginx";
  };

  security.dhparams.params."mail.${hostname}" = 2048;

  services.dovecot2 = {
    enable = true;
    enableImap = true;
    enableLmtp = false;
    enablePAM = false;
    enablePop3 = false;
    mailGroup = virtualMailGroup;
    mailLocation = "maildir:/var/mail/%d/%u";
    mailUser = virtualMailUser;
    modules = [];
    protocols = [ "sieve" ];
    showPAMFailure = false;
    sieveScripts = {
      before = pkgs.writeScript "before.sieve" ''
        require "fileinto";
        if header :contains "X-Spam-Flag" "YES" {
          fileinto "Spam";
          stop;
        } else {
          # The rest goes into INBOX
          # default is "implicit keep", we do it explicitly here
          keep;
        }
      '';
    };
    extraConfig = ''
      namespace inbox {
        inbox = yes

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
      }
    '';
    sslCACert = "/var/lib/acme/mail.${hostname}/fullchain.pem";
    sslServerCert = "/var/lib/acme/mail.${hostname}/cert.pem";
    sslServerKey = "/var/lib/acme/mail.${hostname}/key.pem";
  };

  systemd.services.opendkim-startup = {
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    requiredBy = [ "opendkim.service" ];
    serviceConfig = {
      ExecStart = pkgs.writeScript "opendkim-startup" ''
        #! ${pkgs.bash}/bin/bash
        if (! test -d "${opendkimStateDir}"); then
          mkdir -p "${opendkimStateDir}"
        fi

        if (! test -e "${opendkimStateDir}/default.private"); then
          cd "${opendkimStateDir}"
          "${pkgs.opendkim}/bin/opendkim-genkey" -v -r -d "${hostname}"
          chown "${services.opendkim.user}:${services.opendkim.group}" \
            default.private default.txt
        fi

        if (! test -d "${opendkimRuntimeDir}"); then
          mkdir -p "${opendkimRuntimeDir}"
          chown "${services.opendkim.user}:${services.opendkim.group}" \
            "${opendkimRuntimeDir}"
        fi
      '';
    };
    enable = true;
  };

  # https://git.schneefux.xyz/schneefux/blog/src/master/content/tech/nixos-mailserver.md
  services.opendkim = {
    enable = true;
    domains = "${hostname},mail.${hostname}";
    keyFile = "${opendkimStateDir}/default.private";
    selector = "key";
    socket = "local:${opendkimRuntimeDir}/opendkim.sock";
    user = virtualMailUser;
    group = virtualMailGroup;
  };

  services.spamassassin.enable = true;

  systemd.services.spamassassin-startup = {
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    requiredBy = [ "spamassassin.service" ];
    restartIfChanged = true;
    serviceConfig = {
      ExecStart = pkgs.writeScript "spamassassin-startup" ''
        #! ${pkgs.bash}/bin/bash
        if (! test -d "/etc/spamassassin"); then
          mkdir /etc/spamassassin
        fi

        cd /etc/spamassassin
        ln -sf ${pkgs.spamassassin}/share/spamassassin/20_aux_tlds.cf  .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/active.list .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/init.pre .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/languages .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/local.cf .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/regression_tests.cf .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/sa-update-pubkey.txt .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/user_prefs.template.cf .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/v310.pre .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/v312.pre .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/v320.pre .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/v330.pre .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/v340.pre .
        ln -sf ${pkgs.spamassassin}/share/spamassassin/v341.pre .
      '';
    };
    enable = true;
  };

  users.users."${virtualMailUser}" = {
    home = "/var/mail";
    createHome = true;
    group = virtualMailGroup;
  };

  users.groups = { "${virtualMailGroup}" = {}; };

  # pkgspython27Packages.pypolicyd.spf
}
