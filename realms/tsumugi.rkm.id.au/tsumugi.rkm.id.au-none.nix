# physical specification for none backend

{
  tsumugi =
  { config, lib, pkgs, resources, ...}:
  { deployment.targetEnv = "none";
    deployment.targetHost = "43.229.61.217";

    imports = [ <nixpkgs/nixos/modules/profiles/qemu-guest.nix> ];

    boot.initrd.availableKernelModules = [
      "ata_piix"
      "uhci_hcd"
      "virtio_pci"
      "sr_mod"
      "virtio_blk"
    ];
    boot.kernelModules = [ "kvm-intel" ];
    boot.extraModulePackages = [ ];

    fileSystems."/" = {
      device = "/dev/mapper/vg-root";
      fsType = "ext4";
      options = [ "noatime" "nodiratime" "discard" ];
    };

    fileSystems."/boot" = {
     device = "/dev/vda2";
     fsType = "vfat";
    };

    swapDevices = [{
     device = "/dev/mapper/vg-swap";
    }];

    nix.maxJobs = lib.mkDefault 6;
  };
}
