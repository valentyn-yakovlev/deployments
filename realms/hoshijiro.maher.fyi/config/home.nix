{ config, lib, pkgs, ... }:
let
  localPackages = (import ./../../../local/pkgs/all-packages.nix) {
    inherit config lib pkgs;
  };

  commonPackages = with pkgs; [
    firefox
    localPackages.riot
    nextcloud-client
    chromium
    mpv
    libreoffice
    python27Packages.syncthing-gtk
    kdeconnect
  ];

in {
  home-manager.users = {
    eqyiel = {
      home.packages = commonPackages;
    };

    versapunk = {
      home.packages = commonPackages;
    };

    normie = {
      home.packages = commonPackages;
    };
  };
}
