{ config, lib, pkgs, ... }:

{
  imports = [ ../../lib ];

  mailserver = {
    enable = true;
    domain = "maher.fyi";

    hostPrefix = "tomoyo";
    loginAccounts = {
      ruben = {
        hashedPassword = "$6$i/Mya7uV$g0BqVyInpfxvY5cvCjy9T.HFdq7XuPvZwsiGq9GW4SyyYi4oCXvw7iJu7yasoPvRU2QWhXHFqpOeOvb/6/vr01";
      };
    };
    virtualAliases = {
      "*" = "ruben";
    };
  };

  # services.dovecot2.extraConfig = ''
  #   listen = *
  # '';
}
