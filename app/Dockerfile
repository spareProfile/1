FROM python:3.12

WORKDIR /app
COPY app/requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python3", "app/main.py"]