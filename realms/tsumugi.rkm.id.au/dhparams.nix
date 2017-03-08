{ config, lib, pkgs, ...}:

{
  security.dhparams.path = "/var/lib/dhparams";

  # Create the state dir for security.dhparams.path, it doesn't get created by
  # that service.
  systemd.services.dhparams-startup = {
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    requiredBy = [ "dhparams-init.service" ];
    serviceConfig = {
      ExecStart = pkgs.writeScript "dhparams-startup" ''
        #! ${pkgs.bash}/bin/bash
        if (! test -d "${config.security.dhparams.path}"); then
          mkdir -p "${config.security.dhparams.path}"
        fi
      '';
    };
    enable = true;
  };
}
