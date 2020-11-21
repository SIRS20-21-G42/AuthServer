FROM python:3.7

## FOR DEBUG
# RUN apt install -yqq curl

WORKDIR /auth

COPY requirements.txt /auth
RUN pip3 install -r requirements.txt

COPY ./app/ /auth

# Flask listens by default on port 5000
EXPOSE 5000

# TCP listener
EXPOSE 1337

CMD python3 __init__.py

