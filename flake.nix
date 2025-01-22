{
  description = "Build a tls-attestproxy disk image";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    nixpkgs.url = "github:NixOS/nixpkgs?rev=2fdec2c2e68b7b7845d1ea4e0894c63143e3261b";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, crane, rust-overlay }: flake-utils.lib.eachDefaultSystem (buildSystem:
    flake-utils.lib.eachDefaultSystem (targetSystem:    
      let
        pkgs = import nixpkgs { system = buildSystem; };
        crossPkgs = import nixpkgs { localSystem = buildSystem;
                                     crossSystem = targetSystem;
                                     overlays = [ (import rust-overlay) ];
                                   };
        muslTargets = {
          "x86_64-linux" = "x86_64-unknown-linux-musl";
          "aarch64-linux" = "aarch64-unknown-linux-musl";
        };
        ccTargets = {
          "x86_64-linux" = "x86_64-unknown-linux-gnu-cc";
          "aarch64-linux" = "aarch64-unknown-linux-gnu-cc";
        };
      in
        {
          packages = rec {
            initramcpio = crossPkgs.stdenv.mkDerivation {
              name = "initramcpio";
              src = ./packcpio;
              depsBuildBuild = [pkgs.cpio pkgs.strip-nondeterminism pkgs.xz];
              buildPhase = ''./mkcpio.sh ${crossPkgs.pkgsStatic.busybox}  ${linux} ${attestproxy-crate}/bin/tls-attestproxy'';
            };
            linux = crossPkgs.linuxManualConfig {
              version = crossPkgs.linuxPackages_6_12.kernel.version;
              src = crossPkgs.linuxPackages_6_12.kernel.src;
              configfile = ./linux.cfg;
            };
            xzlinux = pkgs.stdenv.mkDerivation {
              name = "xzlinux";
              src = ./empty;
              buildPhase = ''xz -c --check=crc32 < ${linux}/Image > $out'';
            };
            bootimg = pkgs.stdenv.mkDerivation {
              name = "bootimg";
              src = ./mkbootimg;
              nativeBuildInputs = [pkgs.mtools crossPkgs.grub2_efi pkgs.libfaketime pkgs.dosfstools];
              buildPhase = ''./mkbootimg.sh ${xzlinux} ${initramcpio}'';
            };
            craneLib = (crane.mkLib crossPkgs).overrideToolchain (p: p.rust-bin.stable.latest.default.override {
              targets = [ muslTargets.${targetSystem} ];
            });
            attestproxy-crate = craneLib.buildPackage {
              src = craneLib.cleanCargoSource ./.;
              strictDeps = true;
              
              CARGO_BUILD_TARGET = muslTargets.${targetSystem};
              CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static -C linker=${ccTargets.${targetSystem}}";
            };
            default = bootimg;
          };
        }
    ));
}
