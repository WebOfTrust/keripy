
.PHONY: build-keri
build-keri:
	@docker build --no-cache -f images/keripy.dockerfile --tag gleif/keri:0.6.8 .

.PHONY: build-witness-demo
build-witness-demo:
	@docker build --no-cache -f images/witness.demo.dockerfile --tag gleif/keri-witness-demo:0.6.8 .
