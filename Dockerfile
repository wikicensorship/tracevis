FROM python:3.10.1

WORKDIR /tracevis

ENV PYTHONUNBUFFERED=TRUE

COPY ./ ./

RUN pip install -r requirements.txt

ENTRYPOINT [ "python", "/tracevis/tracevis.py" ]

CMD [ "-h" ]
