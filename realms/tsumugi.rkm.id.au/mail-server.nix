# Don't forget to open ports 993 (imaps), 25 (smtp) and 587 (smtps)!
#
# Heavily inspired by the following:
# https://git.schneefux.xyz/schneefux/blog/src/master/content/tech/nixos-mailserver.md
# http://www.akadia.com/services/postfix_separate_mailboxes.html
# https://tech.tiq.cc/2014/02/how-to-set-up-an-email-server-with-postfix-and-dovecot-without-mysql-on-debian-7/

# TODO: assert that there's not more than one catchAll user configured for a
# domain
# TODO: convert to a module

{ config, lib, pkgs, ... }:
let
  virtualMailUser = "mail";
  virtualMailGroup = "mail";
  mtaUser = "postfix";
  mtaGroup = "postfix";
  virtualMailUserHome = "/var/lib/mail";
  virtualMailUserUID = 1004;
  virtualMailUserGID = 497;
  hostname = "rkm.id.au";
  commonAcmeConfig = (import ./common-acme-config.nix).commonAcmeConfig;
  opendkimStateDir = "/etc/nixos/opendkim";
  opendkimRuntimeDir = "/run/opendkim";
  debug = true;
  domains = {
    "rkm.id.au" = {
      users = [{
        name = "r";
        aliases = [ "root" ];
        catchAll = true;
        sieveScript = ''
          require ["fileinto", "mailbox", "regex"];

          if address :is "from" "notifications@github.com" {
            fileinto :create "GitHub";
            stop;
          }

          # Be sure to use the dot separator if you need to create new folders.
          # I think.
          elsif header :contains "list-id" "nix-dev.lists.science.uu.nl" {
            fileinto :create "Lists.nix-dev";
            stop;
          }

          # This must be the last rule, it will check if list-id is set, and
          # file the message into the Lists folder for further investigation
          elsif header :matches "list-id" "?*" {
            fileinto :create "Lists";
            stop;
          }
        '';
      }];
    };
    "huttriverprovince.com.au" = {
      users = [{
        name = "info";
        aliases = [];
      }];
    };
  };
  mapDomainsToUsers =
    (domains: (lib.flatten (lib.mapAttrsToList
      (domain: props: map ({
        name,
        aliases ? [],         # Other addresses that reach this mailbox.
        catchAll ? false,     # Should this be the catch-all address for this domain?
        sieveScript ? false,  # User's personal sieve script
        password ? "hunter2", # Use dumb default password if the user hasn't set one
        ...
      }: {
        inherit aliases sieveScript catchAll domain name password;
        address = "${name}@${domain}";
      }) props.users) domains)));

  withPasswordFromSecretsFile = map (user@{ address, ... }: user // {
    password = (import ./secrets.nix).mailUsers."${address}".password;
  });
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
     postscreenAccessList = pkgs.writeText "postscreen_access_list.cidr" ''
       # Whitelist domains here, see man 5 postconf: `postscreen_access_list'.
       64.20.227.134 permit # https://mxtoolbox.com
     '';
   in {
     enable = true;
     user = mtaUser;
     group = mtaGroup;
     domain = hostname;
     hostname = "tsumugi.${hostname}";
     sslCACert = "/var/lib/acme/mail.${hostname}/fullchain.pem";
     sslCert = "/var/lib/acme/mail.${hostname}/cert.pem";
     sslKey = "/var/lib/acme/mail.${hostname}/key.pem";
     recipientDelimiter = "+";
     destination = [ "tsumugi.${hostname}" ];
     # rootAlias = "r";
     # postmasterAlias = "r";
     # extraAliases = "eqyiel: r";
    #  virtual = ''
    #    root@${hostname} r@${hostname}
    #    @${hostname} r@${hostname}
    # '';
    mapFiles = {
      virtual_mailbox_maps = pkgs.writeText "virtual_mailbox_maps"
        (lib.concatMapStringsSep "\n"
          ({ address, domain, ... }: "${address} ${domain}/${address}")
            (mapDomainsToUsers domains));
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
        -o smtpd_sasl_path=private/auth
        -o smtpd_sasl_security_options=noanonymous
        -o smtpd_sasl_tls_security_options=noanonymous
        -o smtpd_tls_auth_only=yes
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
       virtual_mailbox_domains = ${(builtins.concatStringsSep ", " (lib.mapAttrsToList (domain: _: domain) domains))}
       virtual_mailbox_maps = hash:/etc/postfix/virtual_mailbox_maps
       virtual_alias_maps = hash:/etc/postfix/virtual_alias_maps
       virtual_minimum_uid = ${toString virtualMailUserUID}
       virtual_uid_maps = static:${toString virtualMailUserUID}
       virtual_gid_maps = static:${toString virtualMailUserGID}
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
       # Some servers (still) can't deal with TLSv1
       # smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
       smtp_tls_protocols = !SSLv2, !SSLv3
       smtp_tls_ciphers = high
       smtpd_tls_security_level = may
       # Some servers (still) can't deal with TLSv1
       # smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
       smtpd_tls_protocols = !SSLv2, !SSLv3
       smtpd_tls_ciphers = high
       smtpd_tls_eecdh_grade = strong
       smtpd_tls_dh1024_param_file = /var/lib/dhparams/mail.${hostname}.pem
       smtpd_tls_session_cache_database = btree:''${data_directory}/smtpd_scache

       smtpd_sasl_auth_enable = yes
       smtpd_sasl_type = dovecot
       smtpd_sasl_path = private/auth

       # See ciphers for outbound connections
       smtp_tls_loglevel = 1
       # See ciphers for inbound connections
       smtpd_tls_loglevel = 1

       smtpd_relay_restrictions =  reject_non_fqdn_recipient
                                   reject_unknown_recipient_domain
                                   permit_mynetworks
                                   reject_unauth_destination

       # Warning: MelbourneIT password reset email bounces if this is set. :(
       #
       # See also: https://serverfault.com/questions/111217
       #
       # See also this thread from the postfix mailing list, copied here for
       # posterity:
       # http://postfix.1071664.n5.nabble.com/is-reject-unknown-client-hostname-safe-now-aka-FCRDNS-td32620.html
       #
       #  Michael Monnerie wrote, at 06/16/2009 02:17 AM:
       # > A big ISP here in Austria started to use reject_unknown_client_hostname
       # > (http://www.postfix.org/postconf.5.html#reject_unknown_client_hostname)
       # > also known as http://en.wikipedia.org/wiki/Forward_Confirmed_reverse_DNS
       # >
       # > Is this option safe today? About 2 years ago it was not, rejecting lots
       # > of good mails. In terms of anti-spam, I'd love to use it, as it should
       # > really help drop a lot of zombie PC's mails in a simple manner. But I'd
       # > like to hear opinions or experience of others.
       #
       # I tried using it for a while last year and found it still to be unsafe.
       # Attempts to contact sites about misconfiguration led nowhere. Maybe if
       # more big ISPs start blocking on the criteria, things will change. One
       # common pattern I noticed with problem sites was the insertion of spam
       # appliances without properly considering DNS. Government and education
       # sites seemed to be particularly unable to understand and correct it. As
       # much as I want to use reject_unknown_client_hostname (it was extremely
       # effective in combatting the few remaining spam that get past my other
       # defenses), I've been increasing the score of RDNS_NONE in SpamAssassin,
       # which will supposedly catch this along with other DNS misconfigurations.
       #
       # In any case, if you want to evaluate it, add this to
       # smtpd_recipient_restrictions (probably best near the end, right before
       # any reject_rbl_client restrictions):
       #
       #  warn_if_reject reject_unknown_client_hostname
       #
       # Monitor your logs for a while to see if you can afford to reject on this
       # criteria. It still indicates that it's unsafe for me to do so.

       smtpd_client_restrictions = permit_mynetworks
                                   # reject_unknown_client_hostname
       smtpd_helo_required = yes
       smtpd_helo_restrictions = permit_mynetworks
                                 reject_non_fqdn_helo_hostname
                                 reject_invalid_helo_hostname
                                 reject_unknown_helo_hostname
       smtpd_data_restrictions = reject_unauth_pipelining

       # OpenDKIM
       milter_default_action = accept
       milter_protocol = 2
       smtpd_milters = unix:${opendkimRuntimeDir}/opendkim.sock
       non_smtpd_milters = unix:${opendkimRuntimeDir}/opendkim.sock

       # Postscreen
       postscreen_access_list =  permit_mynetworks, cidr:${postscreenAccessList}
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
    webroot = "/var/lib/acme/acme-challenge";
    extraDomains = {
      "tsumugi.rkm.id.au" = null;
    };
    postRun = "systemctl reload-or-restart postfix dovecot2";
  };

  security.dhparams.params."mail.${hostname}" = 2048;

  systemd.services.dovecot2-startup = {
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    requiredBy = [ "dovecot2.service" ];
    serviceConfig = let
      createPerDomainPasswdAndShadowFiles = lib.concatMapStringsSep "\n"
        (domain: ''
          test -d "${virtualMailUserHome}/${domain}" \
            || mkdir -p "${virtualMailUserHome}/${domain}" \
            && chown ${virtualMailUser}:${virtualMailGroup} \
              "${virtualMailUserHome}/${domain}"

          test -f "${virtualMailUserHome}/${domain}/passwd" \
            && rm "${virtualMailUserHome}/${domain}/passwd"
          touch "${virtualMailUserHome}/${domain}/passwd"
          chown ${virtualMailUser}:${virtualMailGroup} \
            ${virtualMailUserHome}/${domain}/passwd
          chmod 700 ${virtualMailUserHome}/${domain}/passwd
          test -f "${virtualMailUserHome}/${domain}/shadow" \
            && rm "${virtualMailUserHome}/${domain}/shadow"
          touch "${virtualMailUserHome}/${domain}/shadow"
          chown ${virtualMailUser}:${virtualMailGroup} \
            ${virtualMailUserHome}/${domain}/shadow
          chmod 700 ${virtualMailUserHome}/${domain}/shadow
        '') (lib.mapAttrsToList (domain: _: domain) domains);
      addUsersToPerDomainPasswdAndShadowFiles = lib.concatMapStringsSep "\n"
        ({ address, domain, password, ...}: ''
          echo "${address}::${toString virtualMailUserUID}:${toString virtualMailUserGID}::${virtualMailUserHome}/${domain}/${address}" >> \
            "${virtualMailUserHome}/${domain}/passwd"
          echo "${address}:$(${pkgs.dovecot}/bin/doveadm pw -p ${lib.escapeShellArg password})" >> \
            "${virtualMailUserHome}/${domain}/shadow"
        '') (withPasswordFromSecretsFile (mapDomainsToUsers domains));

      writeUserSieveScript = lib.concatMapStringsSep "\n" (user:
          let userSieveScriptLocation =
            "${virtualMailUserHome}/${user.domain}/${user.address}/.dovecot.sieve";
          in if lib.isString user.sieveScript then ''
            cat << EOF > "${userSieveScriptLocation}"
              ${user.sieveScript}
            EOF
          '' else ''
            test -f "${userSieveScriptLocation}" && rm "${userSieveScriptLocation}"
          '') (mapDomainsToUsers domains);
    in {
      ExecStart = pkgs.writeScript "dovecot2-startup" ''
        #! ${pkgs.bash}/bin/bash
        if (! test -d "${virtualMailUserHome}"); then
          mkdir -p "${virtualMailUserHome}"
          chown ${virtualMailUser}:${virtualMailGroup}
          chmod 700 ${virtualMailUserHome}
        fi

        ${createPerDomainPasswdAndShadowFiles}
        ${addUsersToPerDomainPasswdAndShadowFiles}
        ${writeUserSieveScript}
      '';
    };
    enable = true;
  };

  services.dovecot2 = {
    enable = true;
    enableImap = true;
    enableLmtp = false;
    enablePAM = false;
    enablePop3 = false;
    mailGroup = virtualMailGroup;
    mailLocation = "maildir:${virtualMailUserHome}/%d/%u:LAYOUT=fs:INBOX=${virtualMailUserHome}/%d/%u/INBOX:UTF-8:INDEX=${virtualMailUserHome}/%d/%u/.index:CONTROL=${virtualMailUserHome}/%d/%u/.control";
    mailUser = virtualMailUser;
    modules = [ pkgs.dovecot_pigeonhole ];
    protocols = [ "sieve" ];
    showPAMFailure = false;
    sieveScripts = {
    # Keys must be like this:
    # before, before2, before3, ....
    # after, after2, after3, ...
    # http://wiki2.dovecot.org/Pigeonhole/Sieve/Configuration#Executing_Multiple_Scripts_Sequentially
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
      default_internal_user = dovecot2
      auth_mechanisms = plain login
      # %L means normalise (downcase) usernames, %u is the full username with
      # %the domain appended (example@example.org).
      auth_username_format = %Lu
      disable_plaintext_auth = yes
      ssl = required
      ssl_cipher_list = EDH+CAMELLIA:EDH+aRSA:EECDH+aRSA+AESGCM:EECDH+aRSA+SHA256:EECDH:+CAMELLIA128:+AES128:+SSLv3:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!IDEA:!ECDSA:kEDH:CAMELLIA128-SHA:AES128-SHA
      ssl_dh_parameters_length = 2048
      ssl_prefer_server_ciphers = yes
      ssl_protocols = !SSLv2 !SSLv3 !TLSv1 !TLSv1.1
      mail_privileged_group = ${virtualMailGroup}

      # TODO: enable these lines only if debug is true
      verbose_ssl = yes
      mail_debug = yes
      auth_debug = yes
      auth_debug_passwords = yes

      # k-9 mail chews through these
      mail_max_userip_connections = 50

      mail_uid = ${toString virtualMailUserUID}
      mail_gid = ${toString virtualMailUserGID}
      first_valid_uid = 1000

      lda_mailbox_autosubscribe = yes
      lda_mailbox_autocreate = yes

      passdb {
        args = ${virtualMailUserHome}/%d/shadow
        driver = passwd-file
      }

      userdb {
        args = ${virtualMailUserHome}/%d/passwd
        driver = passwd-file
      }

      service auth {
        unix_listener /var/lib/postfix/queue/private/auth {
          group = ${mtaGroup}
          mode = 0660
          user = ${mtaUser}
        }
        unix_listener auth-master {
          group = ${virtualMailGroup}
          mode = 0660
          user = ${virtualMailUser}
        }
      }

      protocol lda {
        auth_socket_path = /var/run/dovecot2/auth-master
        mail_plugins = $mail_plugins sieve
      }

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

  services.opendkim = {
    enable = true;
    domains = "${hostname},mail.${hostname}";
    keyFile = "${opendkimStateDir}/default.private";
    selector = "key";
    socket = "local:${opendkimRuntimeDir}/opendkim.sock";
    user = mtaUser;
    group = mtaGroup;
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

  users.users = {
    "${virtualMailUser}" = {
      home = virtualMailUserHome;
      createHome = true;
      uid = virtualMailUserUID;
      group = virtualMailGroup;
    };
  };

  users.groups = {
    "${virtualMailGroup}" = {
      gid = virtualMailUserGID;
    };
  };
}
