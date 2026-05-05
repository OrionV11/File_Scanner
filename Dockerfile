FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy project files
COPY . .

# Create uploads folder
RUN mkdir -p uploads

EXPOSE 5000

CMD ["python", "application.py"]
