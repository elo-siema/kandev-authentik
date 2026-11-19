.PHONY: test vet package package-host clean

# Keep VERSION in sync with manifest.yaml.
VERSION := 0.1.0
STAGE := .build/stage
PKG_OUT := kandev-plugin-authentik-$(VERSION).tar.gz
# Sibling kandev checkout providing pkg/pluginsdk (see go.mod replace) and cmd/plugin-pack.
KANDEV_BACKEND := ../kandev/apps/backend

test:
	go test ./...

vet:
	go vet ./...

define stage_package
	rm -rf $(STAGE)
	mkdir -p $(STAGE)/server
	cp manifest.yaml $(STAGE)/manifest.yaml
endef

## Every executable in manifest.yaml.
package:
	$(stage_package)
	GOOS=linux   GOARCH=amd64 go build -o $(STAGE)/server/plugin-linux-amd64       ./server
	GOOS=linux   GOARCH=arm64 go build -o $(STAGE)/server/plugin-linux-arm64       ./server
	GOOS=darwin  GOARCH=amd64 go build -o $(STAGE)/server/plugin-darwin-amd64      ./server
	GOOS=darwin  GOARCH=arm64 go build -o $(STAGE)/server/plugin-darwin-arm64      ./server
	GOOS=windows GOARCH=amd64 go build -o $(STAGE)/server/plugin-windows-amd64.exe ./server
	go -C $(KANDEV_BACKEND) run ./cmd/plugin-pack -dir $(abspath $(STAGE)) -out $(abspath $(PKG_OUT))
	rm -rf $(STAGE)

## Host platform only.
package-host:
	$(stage_package)
	go build -o $(STAGE)/server/plugin-$$(go env GOOS)-$$(go env GOARCH)$$(go env GOEXE) ./server
	go -C $(KANDEV_BACKEND) run ./cmd/plugin-pack -dir $(abspath $(STAGE)) -out $(abspath $(PKG_OUT)) -platform-only
	rm -rf $(STAGE)

clean:
	rm -rf .build kandev-plugin-authentik-*.tar.gz
