#!/bin/bash

echo "Running Python tests..."
cd python
python -m unittest discover tests
cd ..

echo -e "\nRunning PHP tests..."
cd php
composer install
./vendor/bin/phpunit tests
cd ..

echo -e "\nRunning Go tests..."
cd go
go test ./...
cd ..

echo -e "\nRunning Java tests..."
cd java
mvn test
cd .. 