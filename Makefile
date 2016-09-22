NAME ?= homer5
PARAMS ?= -E

all: build start run

.PHONY: build start run
build:
	docker build --tag="qxip/homer-docker-opensips:local" .

start:
	docker run -tid --name $(NAME) qxip/homer-docker-opensips:local $(PARAMS)
