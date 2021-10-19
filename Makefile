.PHONY: interop-bob
interop-bob:
	@docker run --rm -i -p 5620-5621 --name keripy-bob ghcr.io/m00sey/keripy/keripy-interop  bash -c 'python -m keri.demo.demo_bob -e 10'

.PHONY: interop-eve
interop-eve:
	@docker run --rm -i -p 5620-5621 --name keripy-eve ghcr.io/m00sey/keripy/keripy-interop  bash -c 'python -m keri.demo.demo_eve -e 10'

.PHONY: interop-sam
interop-sam:
	@docker run --rm -i -p 5620-5621 --name keripy-sam ghcr.io/WebOfTrust/keripy/keripy-interop  bash -c 'python -m keri.demo.demo_sam -e 10'

.PHONY: build-keri
build-keri:
	@docker build --no-cache -f Dockerfile --tag gleif/keri:0.0.1 .
