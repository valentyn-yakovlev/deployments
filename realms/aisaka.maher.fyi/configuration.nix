{ config, lib, pkgs, ... }:

{
  # imports = [ <nixpkgs/nixos/modules/installer/cd-dvd/sd-image-armv7l-multiplatform.nix> ];
  
  boot.loader.grub.enable = false;

  boot.loader.generic-extlinux-compatible.enable = true;

  boot.loader.generationsDir.enable = false;

  boot.consoleLogLevel = 7;

  boot.kernelParams = [ 
    "dwc_otg.lpm_enable=0"
    "console=ttyAMA0,115200"
    "rootwait"
    "elevator=deadline"
  ];

  boot.kernelPackages = pkgs.linuxPackages_rpi;

  services.nixosManual.enable = false;

  nix.binaryCaches = lib.mkForce [ "http://nixos-arm.dezgeg.me/channel" ];
  nix.binaryCachePublicKeys = [ "nixos-arm.dezgeg.me-1:xBaUKS3n17BZPKeyxL4JfbTqECsT+ysbDJz29kLFRW0=%" ];
  nix.buildCores = 4;

  powerManagement.enable = true;

  nixpkgs.system = "raspberrypi2";
  nixpkgs.config.allowUnfree = true;

  # see nixpkgs issue 24170
  nixpkgs.config.platform = lib.systems.platforms.raspberrypi2;
  # nixpkgs.config.platform = (import <nixpkgs/lib/systems/platforms.nix>).raspberrypi2;
  # nixpkgs.config.platform = pkgs.platforms.raspberrypi2;

  services.sshd.enable = true;

  services.xserver.enable = true;

  services.xserver.videoDrivers = [ "fbdev" ];

  # services.xserver.desktopManager.xfce.enable = true;

  # services.xserver.displayManager.lightdm.enable = true;

  fileSystems = {
    "/boot" = {
      device = "/dev/disk/by-label/NIXOS_BOOT";
      fsType = "vfat";
    };
    "/" = {
      device = "/dev/disk/by-label/NIXOS_SD";
      fsType = "ext4";
    };
  };

  swapDevices = [ { device = "/swapfile"; size = 1024; } ];

  users.mutableUsers = false;

  programs.zsh.enable = true;

  security.sudo.wheelNeedsPassword = false;

  users.users.root = { initialPassword = "hunter2"; };

  users.users.eqyiel = {
    isNormalUser = true;
    uid = 1000;
    initialPassword = "hunter2";
    shell = pkgs.zsh;
    extraGroups = [ "audio" "systemd-journal" "wheel" ];
  };

  nixpkgs.config.packageOverrides = pkgs: {
    llvmPackages_4.llvm = lib.overrideDerivation pkgs.llvmPackages_4.llvm (attrs: { doCheck = false; });
    spidermonkey_17 = lib.overrideDerivation pkgs.spidermonkey_17 (attrs: { doCheck = false; });
    gtk3 = lib.overrideDerivation (pkgs.gtk3.override { waylandSupport = false; }) (attrs: {});
    # webkitgtk = lib.overrideDerivation pkgs.webkitgtk216x (attrs: {
    #   buildInputs = with pkgs; libintlOrEmpty ++ [
    #   gtk2 libwebp enchant libnotify gnutls pcre nettle libidn
    #   libxml2 libsecret libxslt harfbuzz-icu xorg.libpthreadstubs libtasn1 p11_kit
    #   gst_all_1.gst-plugins-base libxkbcommon epoxy at_spi2_core
    #  ] # ++ lib.optional enableGeoLocation geoclue2
    #    ++ (with xlibs; [ libXdmcp libXt libXtst ])
    #    ++ lib.optionals stdenv.isDarwin [ libedit readline mesa ];
    #    # drop wayland for raspberry pi 2 >___>
    #    # ++ optional stdenv.isLinux wayland;
    #  cmakeFlags = [
    #    "-DPORT=GTK"
    #    "-DUSE_LIBHYPHEN=0"
    #  ]
    #  # no egl on raspberry pi
    #  # ++ optional stdenv.isLinux "-DENABLE_GLES2=ON"
    #  ++ ["-DENABLE_GLES2=OFF" "-DENABLE_OPENGL=OFF"];
      webkitgtk216x = lib.overrideDerivation pkgs.webkitgtk216x (attrs: {
        cmakeFlags = [
          "-DPORT=GTK"
          "-DUSE_LIBHYPHEN=0"
        ] ++ [
  "-DENABLE_GLES=OFF"
#  "-DUSE_SYSTEM_MALLOC=ON"
  "-DUSE_ACCELERATE=0"
  "-DENABLE_INTROSPECTION=ON"
  "-DENABLE_MINIBROWSER=OFF"
  "-DENABLE_PLUGIN_PROCESS_GTK2=OFF"
  "-DENABLE_MINIBROWSER=OFF"
  "-DENABLE_VIDEO=ON"
#  "-DENABLE_QUARTZ_TARGET=ON"
  "-DENABLE_X11_TARGET=OFF"
  "-DENABLE_OPENGL=OFF"
  "-DENABLE_WEB_AUDIO=OFF"
  "-DENABLE_WEBGL=OFF"
  "-DENABLE_GRAPHICS_CONTEXT_3D=OFF"
  "-DENABLE_GTKDOC=OFF"
  ];
    });

  };
}
