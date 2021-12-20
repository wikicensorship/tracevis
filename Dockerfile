FROM python:3.10.1-slim-bullseye

ENV PYTHONUNBUFFERED=TRUE

ENV TRACEVIS_OUTPUT_DIR=/tracevis_data/

RUN mkdir -p /tracevis_data

WORKDIR /tracevis

# Install requirements before copying whole source. (used for quick build)
COPY requirements.txt .

RUN pip install -r requirements.txt

COPY . .

ENTRYPOINT [ "python", "tracevis.py" ]

CMD [ "-h" ]