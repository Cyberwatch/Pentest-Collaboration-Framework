FROM python:3.9
RUN mkdir /pcf
ADD . /pcf
WORKDIR /pcf
RUN pip install -r requirements_unix.txt
ENTRYPOINT pip install -r requirements_unix.txt; if [ ! -e "./configuration/database.sqlite3" ]; then echo 'DELETE_ALL' | python new_initiation.py; fi && python run.py