{ ... }:

{
  imports = [
    ./containers
    ./mail-server.nix
    ./home.nix
    ./matrix.nix
  ];
}
