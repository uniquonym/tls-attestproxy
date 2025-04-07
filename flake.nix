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
        pkgs = import nixpkgs { system = buildSystem; overlays = [ (import rust-overlay) ]; };
        crossPkgs = if buildSystem == targetSystem then
          pkgs
        else
          import nixpkgs { system = buildSystem;
                           crossSystem = targetSystem;
                           overlays = [ (import rust-overlay) ];
                         }
        ;
        muslTargets = {
          "x86_64-linux" = "x86_64-unknown-linux-musl";
          "aarch64-linux" = "aarch64-unknown-linux-musl";
        };
        ccTargets = {
          "x86_64-linux" = "x86_64-unknown-linux-gnu-cc";
          "aarch64-linux" = "aarch64-unknown-linux-gnu-cc";
        };
        craneLib = (crane.mkLib crossPkgs).overrideToolchain (p: p.rust-bin.stable.latest.default.override {
          targets = [ muslTargets.${targetSystem} ];
        });
        src = craneLib.cleanCargoSource ./.;
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
            xzlinux = if targetSystem == "x86_64-linux" then linux else pkgs.stdenv.mkDerivation {
              name = "xzlinux";
              src = ./empty;
              buildPhase = ''xz -c --check=crc32 < ${linux}/Image > $out'';
            };
            # Derived from nixpkgs, but changed to a recent version that builds with recent compilers.
            pesign = pkgs.stdenv.mkDerivation rec {
              pname = "pesign";
              version = "d734b6a00c95eaf205d713ea580a9df8f9b6c1ec";

              src = pkgs.fetchFromGitHub {
                owner = "rhboot";
                repo = "pesign";
                rev = "d734b6a00c95eaf205d713ea580a9df8f9b6c1ec";
                hash = "sha256-evbDa74eiROBD/2IIyE494qmHloCxF7NX3sMPVYJIyE=";
              };

              # nss-util is missing because it is already contained in nss
              # Red Hat seems to be shipping a separate nss-util:
              # https://centos.pkgs.org/7/centos-x86_64/nss-util-devel-3.44.0-4.el7_7.x86_64.rpm.html
              # containing things we already have in `nss`.
              # We can ignore all the errors pertaining to a missing
              # nss-util.pc I suppose.
              buildInputs = [
                pkgs.efivar
                pkgs.util-linux
                pkgs.nss
                pkgs.popt
                pkgs.nspr
                pkgs.mandoc
              ];
              nativeBuildInputs = [ pkgs.pkg-config ];

              makeFlags = [ "INSTALLROOT=$(out)" ];

              postInstall = ''
                mv $out/usr/bin $out/bin
                mv $out/usr/share $out/share

                rm -rf $out/usr
                rm -rf $out/etc
                rm -rf $out/run
              '';
            };
            bootimg = pkgs.stdenv.mkDerivation {
              name = "bootimg";
              src = ./mkbootimg;
              nativeBuildInputs = [pkgs.mtools crossPkgs.grub2_efi pkgs.libfaketime pkgs.dosfstools pesign];
              buildPhase = ''./mkbootimg.sh ${targetSystem} ${xzlinux} ${initramcpio} ${./snakeoil-pesign/nss}'';
            };
            attestproxy-crate = craneLib.buildPackage {
              strictDeps = true;
              inherit (craneLib.crateNameFromCargoToml { inherit src; pname = "tls-attestproxy"; }) version;
              inherit src;
              pname = "tls-attestproxy";
              cargoExtraArgs = "-p tls-attestproxy";
              buildInputs = [ pkgs.tpm2-tss ];
              nativeBuildInputs = [ pkgs.pkg-config ];
              CARGO_BUILD_TARGET = muslTargets.${targetSystem};
              CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static -C linker=${if targetSystem == buildSystem then "cc" else ccTargets.${targetSystem}}";
            };
            default = bootimg;
          };
        }
    ));
}
