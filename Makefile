
.PHONY: build-keri
build-keri:
	@docker buildx build --platform=linux/amd64 --no-cache -f images/keripy.dockerfile --tag weboftrust/keri:1.1.0 .

.PHONY: build-witness-demo
build-witness-demo:
	@@docker buildx build --platform=linux/amd64 --no-cache -f images/witness.demo.dockerfile --tag weboftrust/keri-witness-demo:1.1.0 .

.PHONY: publish-keri
publish-keri:
	@docker push weboftrust/keri --all-tags

.PHONY: publish-keri-witness-demo
publish-keri-witness-demo:
	@docker push weboftrust/keri-witness-demo --all-tags