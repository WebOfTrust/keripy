
.PHONY: build-keri build-witness-demo publish-keri-witness-demo publish-keri

VERSION=1.2.7
REGISTRY=gleif
IMAGE=keri
LATEST_TAG=$(REGISTRY)/$(IMAGE):latest
VERSIONED_TAG=$(REGISTRY)/$(IMAGE):$(VERSION)

define DOCKER_WARNING
In order to use the multi-platform build enable the containerd image store
The containerd image store is not enabled by default.
To enable the feature for Docker Desktop:
	Navigate to Settings in Docker Desktop.
	In the General tab, check Use containerd for pulling and storing images.
	Select Apply and Restart."
endef

build-keri: .warn
	@docker build \
		--platform=linux/amd64,linux/arm64 \
		-f images/keripy.dockerfile \
		-t $(VERSIONED_TAG) \
		-t $(LATEST_TAG) .

build-witness-demo: .warn
	@docker build \
		--platform=linux/amd64,linux/arm64 \
		-f images/witness.demo.dockerfile \
		-t $(REGISTRY)/keri-witness-demo:$(VERSION) .

publish-keri-witness-demo:
	@docker push $(REGISTRY)/keri-witness-demo --all-tags

publish-keri:
	@docker push $(REGISTRY)/$(IMAGE) --all-tags

.warn:
	@echo -e ${RED}"$$DOCKER_WARNING"${NO_COLOUR}

RED="\033[0;31m"
NO_COLOUR="\033[0m"
export DOCKER_WARNING
