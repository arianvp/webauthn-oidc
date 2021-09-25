{
  description = "EKS Experiment";

  inputs.utils.url = "github:numtide/flake-utils";

  outputs = { self, utils, nixpkgs }:
    utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in
      {
        devShell = with pkgs; mkShell {
          nativeBuildInputs = [
            go
          ];
        };
      });
}
