FROM python:3.10.1-slim-bullseye

ENV PYTHONUNBUFFERED=TRUE

ENV TRACEVIS_OUTPUT_DIR=/tracevis_data/

RUN mkdir -p /tracevis_data

WORKDIR /tracevis

COPY ./ ./

RUN pip install -r requirements.txt

ENTRYPOINT [ "python", "/tracevis/tracevis.py" ]

CMD [ "-h" ]
