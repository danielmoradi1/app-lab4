# Lab Web Application, Container & Supply-Chain Security

## Part A (Insecure Application)
### run from the application från app_insecure
#### Active the venv
- source venv/bin/activate

#### Initiera the DB
- cd app_insecure
- sqlite3 data/db.sqlite3 < app_insecure/db_init.sql

#### Run the application
- python app.py or flask run
- host: http://127.0.0.1:5000


## Part A (Secure Application)
- source venv/bin/activate

#### Initiera the DB
- cd app_secure
- sqlite3 data/db.sqlite3 < app_secure/db_init.sql

#### Start the application
- python app.py or flask run
- http://127.0.0.1:5001


