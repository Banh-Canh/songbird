{
  pkgs ? (
    import <nixpkgs> {
      config.allowUnfree = true;
    }
  ),
  ...
}:
pkgs.mkShell {
  buildInputs = [
    pkgs.go
  ];
  packages = [
    (pkgs.writeShellScriptBin "songbird" ''
      #!/bin/bash
        $(nix-build .)/bin/songbird "$@"
    '')
  ];
}
