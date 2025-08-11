{
  pkgs ? import <nixpkgs> { },
}:
let
  cleanExamplesFilter =
    name: type:
    let
      parentDir = baseNameOf (dirOf name);
    in
    !(parentDir == "examples" && (pkgs.lib.hasSuffix ".pdf" name));

  cleanDocsFilter =
    name: type:
    let
      parentDir = baseNameOf (dirOf name);
    in
    !(parentDir == "docs" && (pkgs.lib.hasSuffix ".md" name));

  cleanSource =
    src:
    pkgs.lib.cleanSourceWith {
      filter = cleanExamplesFilter;
      src = pkgs.lib.cleanSourceWith {
        filter = cleanDocsFilter;
        src = pkgs.lib.cleanSource src;
      };
    };
  build = pkgs.buildGoModule {
    pname = "songbird";
    version = "nix";

    src = cleanSource ./.;
    ldflags = [
      "-s"
      "-w"
      "-X github.com/Banh-Canh/songbird/cmd.version=nix"
    ];

    vendorHash = "sha256-5CDfg/qnhCmR32tft4NFBsH2BM8Ca9m1wymoHL4BQl8=";

    subPackages = [ "." ];
  };
in
build
