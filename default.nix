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

  cleanReadmeFilter = name: type: !(baseNameOf name == "README.md" && baseNameOf (dirOf name) == ".");

  cleanSource =
    src:
    pkgs.lib.cleanSourceWith {
      filter = cleanExamplesFilter;
      src = pkgs.lib.cleanSourceWith {
        filter = cleanDocsFilter;
        src = pkgs.lib.cleanSourceWith {
          filter = cleanReadmeFilter;
          src = pkgs.lib.cleanSource src;
        };
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

    vendorHash = "sha256-mrnAQTmG+KkCjvS1Efgt0NCaLR3KbQYo2MBe6VY9LL0=";

    subPackages = [ "." ];
  };
in
build
