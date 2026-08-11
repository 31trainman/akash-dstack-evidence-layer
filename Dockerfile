FROM python:3.12-alpine
WORKDIR /app
COPY app.py /app/app.py
ENV PORT=8080
ENV CONFIG_ID=akash-dstack-poc-v0.2
EXPOSE 8080
CMD ["python", "/app/app.py"]
