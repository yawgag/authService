.PHONY: build up test down

build:
	@docker-compose build

up:
	@docker-compose up -d

test:
	@docker-compose -f docker-compose.test.yml up --abort-on-container-exit --build

down:
	@docker-compose down
