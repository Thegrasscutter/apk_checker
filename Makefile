.PHONY: build run clean

IMAGE_NAME = apk-playbook
CONTAINER_NAME = apk-playbook-container

build:
	docker build -t $(IMAGE_NAME) .

run:
	docker run --rm --name $(CONTAINER_NAME) -v $(PWD)/output:/output $(IMAGE_NAME)
run-bash:
	docker run --rm -it --name $(CONTAINER_NAME) -v $(PWD)/output:/output $(IMAGE_NAME) /bin/bash
clean:
	docker rmi $(IMAGE_NAME) || true
	docker rm $(CONTAINER_NAME) || true