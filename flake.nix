{
  description = "Build a tls-attestproxy disk image";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, crane }: flake-utils.lib.eachDefaultSystem (system:
    let pkgs = import nixpkgs { inherit system; }; in
    {
      packages = rec {
        initramcpio = pkgs.stdenv.mkDerivation {
          name = "initramcpio";
          src = ./packcpio;
          depsBuildBuild = [pkgs.cpio pkgs.strip-nondeterminism pkgs.xz];
          buildPhase = ''./mkcpio.sh ${pkgs.pkgsStatic.busybox}  ${pkgs.linuxPackages_latest.kernel}'';
        };
        xzlinux = pkgs.stdenv.mkDerivation {
          name = "xzlinux";
          src = pkgs.linuxPackages_latest.kernel;
          buildPhase = ''xz -c --check=crc32 < Image > $out'';
        };
        bootimg = pkgs.stdenv.mkDerivation {
          name = "bootimg";
          src = ./mkbootimg;
          nativeBuildInputs = [pkgs.mtools pkgs.grub2_efi pkgs.libfaketime pkgs.dosfstools];
          buildPhase = ''./mkbootimg.sh ${xzlinux} ${initramcpio}'';
        };
        default = bootimg;
      };
    }
  );
}
