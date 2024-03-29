{
  description = "EKS Experiment";

  inputs.utils.url = "github:numtide/flake-utils";

  outputs = { self, utils, nixpkgs }:
    {
      nixosModule = { config, lib, ... }:
        let cfg = config.services.webauthn-oidc; in
        {
          options.services.webauthn-oidc = {
            host = lib.mkOption {
              type = lib.types.str;
            };
            port = lib.mkOption {
              type = lib.types.str;
              default = "8080";
            };
            createNginxConfig = lib.mkEnableOption "enable nginx config";
          };
          config = {
            services.nginx.virtualHosts."${cfg.host}" = lib.mkIf cfg.createNginxConfig {
              forceSSL = true;
              enableACME = true;
              locations."/".proxyPass = "http://localhost:8080";
            };
            systemd.services.webauthn-oidc = {
              wantedBy = [ "multi-user.target" ];
              script = "${self.defaultPackage.${config.nixpkgs.system}}/bin/webauthn-oidc -no-tls -port ${cfg.port} -relying-party-id ${cfg.host} -origin https://${cfg.host}";
            };
          };
        };

    }
    //
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
          src =  pkgs.lib.cleanSource ./.;
          vendorHash = "sha256-jOvu1JhTD7H7sL9uSo3rGx7Tl/XveaUSN5Id0ImIaMc=";
        };

        devShell = with pkgs; mkShell {
          nativeBuildInputs = [
            bashInteractive
            go
            kind
            kubectl
            kubelogin-oidc
          ];
        };
      });
}

