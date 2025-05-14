# Use an official Python runtime as a base image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy all files to the working directory
COPY . /app

# Install required Python packages
RUN pip install --no-cache-dir flask flask-wtf flask-bcrypt

# Expose the port Flask will run on
EXPOSE 9025

# Run the application
CMD ["python", "app.py"]
