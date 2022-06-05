FROM python:3.10-alpine

ENV PYTHONUNBUFFERED 1

ENV TRACEVIS_OUTPUT_DIR=/tracevis_data/

WORKDIR /tracevis

# Install requirements before copying whole source. (used for quick build)
COPY requirements.txt .

RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT [ "python", "tracevis.py" ]

CMD [ "-h" ]
