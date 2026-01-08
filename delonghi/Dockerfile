FROM python:3.12-alpine

WORKDIR /app

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

RUN pip install --no-cache-dir requests pycryptodome

COPY delonghi.py /app/delonghi.py
COPY run.sh /app/run.sh
COPY data/ /data/

RUN chmod +x /app/run.sh

CMD ["/app/run.sh"]
