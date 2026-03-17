{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{
      nixpkgs,
      crane,
      flake-parts,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = nixpkgs.lib.systems.flakeExposed;

      perSystem =
        { pkgs, ... }:
        let
          craneLib = crane.mkLib pkgs;

          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: type:
              (builtins.match ".*\\.html$" path != null)
              || (builtins.match ".*\\.css$" path != null)
              || (craneLib.filterCargoSources path type);
          };

          commonArgs = {
            inherit src;
            strictDeps = true;
            nativeBuildInputs = [ pkgs.pkg-config ];
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          agpscape-unwrapped = craneLib.buildPackage (commonArgs // { inherit cargoArtifacts; });

          agpscape = pkgs.runCommand "agpscape" { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
            mkdir -p $out/bin $out/share/agpscape
            cp -r ${./static} $out/share/agpscape/static
            cp -r ${./templates} $out/share/agpscape/templates
            makeWrapper ${agpscape-unwrapped}/bin/agpscape $out/bin/agpscape \
              --run 'cd ${placeholder "out"}/share/agpscape'
          '';
        in
        {
          packages.default = agpscape;

          devShells.default = craneLib.devShell { packages = [ pkgs.cargo-watch ]; };
        };
    };
}
