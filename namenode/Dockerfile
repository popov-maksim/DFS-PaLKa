FROM ubuntu:latest
WORKDIR /workdir

ENV FLASK_APP src/name_node.py
ENV FLASK_RUN_HOST 0.0.0.0
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

EXPOSE 80

RUN apt-get update
RUN apt-get install -y python3-venv python3-pip
RUN apt-get install -y redis-server
RUN sed -i "s/bind .*/bind 127.0.0.1/g" /etc/redis/redis.conf


ADD . /workdir
ADD ./namenode /workdir

RUN echo `ls -1`
RUN python3 -m venv --clear venv
RUN python3 -m pip install -r requirements.txt


CMD ["bash", "deployment_namenode.sh"]
