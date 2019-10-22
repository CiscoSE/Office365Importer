FROM python:3

ADD config.json /app/
ADD requirements.txt /app/
ADD office_365_importer.py /app/
ADD stealthwatch_client.py /app/

WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "-u", "office_365_importer.py", "-d"]
