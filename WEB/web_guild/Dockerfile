FROM python:3.11-alpine
WORKDIR /app
COPY guild/ /app
RUN pip install -r requirements.txt
EXPOSE 1337
ENTRYPOINT ["python", "main.py"]