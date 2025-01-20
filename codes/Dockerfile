FROM python:3.11.4-alpine

WORKDIR /codes

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PATH="/PY/BIN:$PATH"

RUN pip install --upgrade pip

COPY . /codes

RUN pip install -r requirements.txt

CMD ["gunicorn","__workers", "3", "config.wsgi:application", "bind", "0.0.0.0:8000"]