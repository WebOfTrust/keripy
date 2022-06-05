#!/bin/bash

# OOBI between local QARs
curl -s -X POST "http://localhost:5626/oobi/qar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"IntGAR\", \"url\":\"http://127.0.0.1:5642/oobi/ESQjNQnVk1N8nTdS7g6m17IWD0iuliABV-RMA-drjgIs/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5627/oobi/qar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"IntGAR\", \"url\":\"http://127.0.0.1:5642/oobi/ESQjNQnVk1N8nTdS7g6m17IWD0iuliABV-RMA-drjgIs/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq

# OOBI between local IntGARs
curl -s -X POST "http://localhost:5624/oobi/intgar1" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"QVI\", \"url\":\"http://127.0.0.1:5642/oobi/ESrWiCbP5K0Q7-m1e3GPaY8HJCvqioEIIJhqpz16zk6w/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
curl -s -X POST "http://localhost:5625/oobi/intgar2" -H "accept: */*" -H "Content-Type: application/json" -d "{\"oobialias\": \"QVI\", \"url\":\"http://127.0.0.1:5642/oobi/ESrWiCbP5K0Q7-m1e3GPaY8HJCvqioEIIJhqpz16zk6w/witness/BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo\"}" | jq
sleep 3

curl -s -X POST 'http://localhost:5624/challenge/IntGAR'  -H "accept: */*" -H "Content-Type: application/json" -d '{"recipient":"ESrWiCbP5K0Q7-m1e3GPaY8HJCvqioEIIJhqpz16zk6w","words":["final","hard","reveal","car","city","style","throw","slim","smile","jeans","math","liberty"]}'
curl -s -X POST 'http://localhost:5625/challenge/IntGAR'  -H "accept: */*" -H "Content-Type: application/json" -d '{"recipient":"ESrWiCbP5K0Q7-m1e3GPaY8HJCvqioEIIJhqpz16zk6w","words":["final","hard","reveal","car","city","style","throw","slim","smile","jeans","math","liberty"]}'