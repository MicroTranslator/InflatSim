let
  name = "InflatSim";
  # pin nixpkgs to current stable version (22.11)
  pkgsSrc = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/50c23cd4ff6c8344e0b4d438b027b3afabfe58dd.tar.gz";
    sha256 = "07rs6d06sg84b5nf9zwjczzbam1f3fax3s2i9kp65fdbbskqp5zs";
  };
  pkgs = import pkgsSrc {};
  capstone-next = pkgs.capstone.overrideAttrs (old: {
    version = "next-5.0.0";
    src = pkgs.fetchFromGitHub {
      owner = "capstone-engine";
      repo = "capstone";
      rev = "6eb1db9c04113ac0a05f2dfd228704c84775530f";
      hash = "sha256-ejshOt02jaAJkuyS8T+T6v3Td4Jqg19zKgVMZ5VuISs=";
    };
  });
in pkgs.mkShell {
  inherit name;
  buildInputs = with pkgs; [
    glib.dev
    glib.out
    qemu
    capstone-next
  ];
  shellHook = ''
    NIX_CFLAGS_COMPILE+=" -isystem ${pkgs.glib.dev}/include/glib-2.0"
    NIX_CFLAGS_COMPILE+=" -isystem ${pkgs.glib.out}/lib/glib-2.0/include"
  '';
}
