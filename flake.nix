{
  description = "EKS Experiment";

  inputs.utils.url = "github:numtide/flake-utils";

  outputs = { self, utils, nixpkgs }:
    utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in
      {
        packages.container = pkgs.dockerTools.buildLayeredImage {
          name = self.defaultPackage.${system}.pname;
          contents = [
            self.defaultPackage.${system}
          ];
        };

        packages.streamContainer = pkgs.dockerTools.streamLayeredImage {
          name = self.defaultPackage.${system}.pname;
          contents = [
            self.defaultPackage.${system}
          ];
        };


        defaultPackage = pkgs.buildGoModule {
          pname = "webauthn-oidc";
          version = "0.0.1";
          src = ./.;
          vendorSha256 = "sha256-NjX2BqKhZNP2KHbT75m5+nfqV9OaTKUgdxg7K0eE4lM=";
        };

        devShell = with pkgs; mkShell {
          nativeBuildInputs = [
            go
            mkcert
            kind
            kubectl
            kubelogin-oidc
          ];
        };
      });
}
