{ config, lib, pkgs, ... }:
let
  localPackages = (import ./../../../local/pkgs/all-packages.nix) {
    inherit config lib pkgs;
  };

in {
  home-manager.users = {
    eqyiel = {
      services.syncthing.enable = true;
    };
  };
}
