# Don't forget to open ports 993 (imaps), 25 (smtp) and 587 (smtps)!

{ config, lib, pkgs, ... }:
let
  virtualMailUser = "mail";
  virtualMailGroup = "mail";
  virtualMailUserHome = "/var/lib/mail";
  virtualMailUserUID = 1004;
  virtualMailUserGID = 497;
  hostname = "rkm.id.au";
  commonAcmeConfig = (import ./common-acme-config.nix).commonAcmeConfig;
  opendkimStateDir = "/etc/nixos/opendkim";
  opendkimRuntimeDir = "/run/opendkim";
  bccSelfUsers = [ "r@rkm.id.au" ];
  domains = {
    "rkm.id.au" = {
      users = [{
        name = "r";
        aliases = [ "root" ];
        catchAll = true;
        bccSelf = true;
      }];
    };
    "huttriverprovince.com.au" = {
      users = [{ name = "info"; aliases = []; }];
    };
  };
  mapDomainsToUsers =
    (domains: (lib.flatten (lib.mapAttrsToList
      (domain: props: map ({
        name,
        # Other addresses that reach this mailbox.
        aliases ? [],
        # Should this be the catch-all address for this domain?
        # TODO: make sure this isn't set for more than one user.
        catchAll ? false,
         # If this is true, mark mail coming from these users as \\Seen.
         # This is useful if you configure your mail client to BCC self for
         # nicer threading.
        bccSelf ? false,
        ...
      }: {
        inherit name aliases catchAll domain bccSelf;
        address = "${name}@${domain}";
      }) props.users) domains)));
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
     domain = hostname;
     hostname = "mail.${hostname}";
     sslCACert = "/var/lib/acme/mail.${hostname}/fullchain.pem";
     sslCert = "/var/lib/acme/mail.${hostname}/cert.pem";
     sslKey = "/var/lib/acme/mail.${hostname}/key.pem";
     recipientDelimiter = "+";
     destination = [ "${hostname}" "mail.${hostname}" ];
     rootAlias = "r";
     postmasterAlias = "r";
     extraAliases = "eqyiel: r";
     virtual = ''
       root@${hostname} r@${hostname}
       @${hostname} r@${hostname}
    '';
    mapFiles = {
      virtual_mailbox_maps = pkgs.writeText "virtual_mailbox_maps"
        (lib.concatMapStringsSep "\n"
          ({ address, domain, ... }: "${address} ${domain}/${address}")
            (mapDomainsToUsers domains));
      virtual_mailbox_domains = pkgs.writeText "virtual_mailbox_domains"
        (builtins.concatStringsSep "\n"
          (lib.mapAttrsToList (domain: _: domain) domains));
    };
    aliasFiles = {
      virtual_alias_maps = pkgs.writeText "virtual_alias_maps"
      (builtins.concatStringsSep "\n"
        (lib.concatMap (user:
          (map (alias: "${alias}@${user.domain} ${user.address}") user.aliases)
           ++ (if user.catchAll then [
             "@${user.domain} ${user.address}"
           ] else []))
          (builtins.filter (user:
            (builtins.length user.aliases) > 0 || user.catchAll)
              (mapDomainsToUsers domains))));
    };
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
      dovecot unix  - n n - - pipe
        flags=DRhu user=${virtualMailUser}:${virtualMailGroup} argv=${pkgs.spamassassin}/bin/spamc -f -u spamd -e ${pkgs.dovecot}/libexec/dovecot/dovecot-lda -f ''${sender} -d ''${recipient}
    '';
     extraConfig = ''
       virtual_mailbox_base = ${virtualMailUserHome}
       virtual_mailbox_domains = hash:/etc/postfix/virtual_mailbox_domains
       virtual_mailbox_maps = hash:/etc/postfix/virtual_mailbox_maps
       virtual_alias_maps = hash:/etc/postfix/virtual_alias_maps
       virtual_minimum_uid = ${virtualMailUserUID}
       virtual_uid_maps = static:${virtualMailUserUID}
       virtual_gid_maps = static:${vitualMailUserGID}
       virtual_transport = dovecot
       dovecot_destination_recipient_limit = 1
       mailbox_size_limit = 0

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
       smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
       smtp_tls_ciphers = high
       smtpd_tls_security_level = may
       smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
       smtpd_tls_ciphers = high
       smtpd_tls_eecdh_grade = strong
       smtpd_tls_dh1024_param_file=/var/lib/dhparams/mail.${hostname}.pem
       smtpd_tls_session_cache_database = btree:''${data_directory}/smtpd_scache

       # See ciphers for outbound connections
       smtp_tls_loglevel = 1
       # See ciphers for inbound connections
       smtpd_tls_loglevel = 1

       smtpd_relay_restrictions =  reject_non_fqdn_recipient
                                   reject_unknown_recipient_domain
                                   permit_mynetworks
                                   reject_unauth_destination
       smtpd_client_restrictions = permit_mynetworks
                                   reject_unknown_client_hostname
       smtpd_helo_required = yes
       smtpd_helo_restrictions = permit_mynetworks
                                 reject_invalid_helo_hostname
                                 reject_non_fqdn_helo_hostname
                                 reject_unknown_helo_hostname
       smtpd_data_restrictions = reject_unauth_pipelining
       mailbox_transport = lmtp:inet:127.0.0.1:8458

       # OpenDKIM
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
    postRun = "systemctl reload-or-restart postfix dovecot2";
  };

  security.dhparams.params."mail.${hostname}" = 2048;

  systemd.services.dovecot2-startup = {
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    requiredBy = [ "dovecot2.service" ];
    serviceConfig = {
      ExecStart = pkgs.writeScript "dovecot2-startup" ''
        #! ${pkgs.bash}/bin/bash
        if (! test -d "${virtualMailUserHome}"); then
          mkdir -p "${virtualMailUserHome}"
          chown ${virtualMailUser}:${virtualMailGroup}
          chmod 700 ${virtualMailUserHome}
        fi


      '';
    };
    enable = true;
  };

  services.dovecot2 = {
    enable = true;
    enableImap = true;
    enableLmtp = true;
    enablePAM = true;
    enablePop3 = false;
    mailGroup = virtualMailGroup;
    mailLocation = "maildir:~/mail:LAYOUT=fs:INBOX=~/mail/INBOX:UTF-8:INDEX=~/mail/.index:CONTROL=~/mail/.control";
    mailUser = virtualMailUser;
    modules = [ pkgs.dovecot_pigeonhole ];
    protocols = [ "sieve" ];
    showPAMFailure = true;
    sieveScripts = { # http://wiki2.dovecot.org/Pigeonhole/Sieve/Configuration#Executing_Multiple_Scripts_Sequentially
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
      before2 = let
        body = lib.concatMapStringsSep "elsif " (x: ''
          envelope "from" "${x}" {
            setflag "\\Seen";
            # Unfortunately setflag doesn't work with implicit or explicit keep.
            # Workaround is to file into INBOX.
            fileinto "INBOX";
          }
        '') (map ({ address, ... }: address)
              (lib.filter ({ bccSelf, ... }: bccSelf)
                (mapDomainsToUsers domains)));
      in pkgs.writeScript "before2.sieve" ''
        # Hack to make mail threading more pleasant.  Configure mail client to
        # BCC-self, those mails will get marked as read.
        require ["envelope", "imap4flags", "fileinto"];
        if ${body}
      '';
      before3 = pkgs.writeScript "before3.sieve" ''
        require ["fileinto", "body", "mailbox"];
        if body :contains ["Unsubscribe", "unsubscribe"] {
          fileinto :create "Marketing Spam";
        }
      '';
    };
    extraConfig = ''
      default_internal_user = dovecot2
      auth_mechanisms = plain login
      auth_username_format = %Ln
      disable_plaintext_auth = yes
      ssl = required
      ssl_cipher_list = EDH+CAMELLIA:EDH+aRSA:EECDH+aRSA+AESGCM:EECDH+aRSA+SHA256:EECDH:+CAMELLIA128:+AES128:+SSLv3:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!IDEA:!ECDSA:kEDH:CAMELLIA128-SHA:AES128-SHA
      ssl_dh_parameters_length = 2048
      ssl_prefer_server_ciphers = yes
      ssl_protocols = !SSLv2 !SSLv3 !TLSv1 !TLSv1.1
      mail_privileged_group = ${virtualMailGroup}

      verbose_ssl = yes
      mail_debug = yes
      auth_debug = yes
      auth_debug_passwords = yes

      mail_uid = ${virtualMailUserUID}
      mail_uid = ${virtualMailUserGID}
      first_valid_uid = ${virtualMailUserUID}

      lda_mailbox_autosubscribe = yes
      lda_mailbox_autocreate = yes

      passdb {
        args = /var/lib/mail/%d/shadow
        driver = passwd-file
      }

      userdb {
        args = /var/lib/mail/%d/passwd
        driver = passwd-file
      }

      service auth {
        unix_listener /var/spool/postfix/private/auth {
          group = mail
          mode = 0660
          user = mail
        }
        unix_listener auth-master {
          group = mail
          mode = 0660
          user = mail
        }
      }

      protocol lda {
        auth_socket_path = /var/run/dovecot/auth-master
        mail_plugins = $mail_plugins sieve
      }

      # protocol lmtp {
      #   mail_plugins = $mail_plugins sieve
      # }

      # service lmtp {
      #   inet_listener {
      #     port = 8458
      #   }
      # }

      # service auth {
      #   inet_listener {
      #     port = 2847
      #   }
      # }

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

        mailbox "Marketing Spam" {
          auto = subscribe
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
    home = virtualMailUserHome;
    createHome = true;
    uid = virtualMailUserUID;
    gid = virtualMailUserGID;
    group = virtualMailGroup;
  };

  users.groups = { "${virtualMailGroup}" = {}; };

  # pkgspython27Packages.pypolicyd.spf
}
