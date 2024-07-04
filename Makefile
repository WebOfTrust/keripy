
.PHONY: build-keri
build-keri:
	@docker buildx build --platform=linux/amd64 -f images/keripy.dockerfile --tag weboftrust/keri:1.1.16 .
	@docker buildx build --platform=linux/arm64 -f images/keripy.dockerfile --tag weboftrust/keri:1.1.16-arm64 .

.PHONY: build-witness-demo
build-witness-demo:
	@@docker buildx build --platform=linux/amd64 -f images/witness.demo.dockerfile --tag weboftrust/keri-witness-demo:1.1.16 .
	@@docker buildx build --platform=linux/arm64 -f images/witness.demo.dockerfile --tag weboftrust/keri-witness-demo:1.1.16-arm64 .

.PHONY: publish-keri
publish-keri:
	@docker push weboftrust/keri --all-tags

.PHONY: publish-keri-witness-demo
publish-keri-witness-demo:
	@docker push weboftrust/keri-witness-demo --all-tags