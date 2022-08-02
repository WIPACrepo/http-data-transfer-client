FROM python:3.8

RUN useradd -m -U app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /home/app
USER app

COPY . .

ENV PYTHONPATH=/home/app

ENTRYPOINT ["python", "-m", "http_data_transfer_client"]

CMD ["-h"]
